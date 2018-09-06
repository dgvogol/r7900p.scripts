#! /usr/bin/python3

# todo:
# - collect build logs, separate them from make database dup

import re
from io import StringIO
import logging
import argparse
import sys, os
import pickle
import posixpath

MK_DB_PRINT_BEGIN = '# Make data base, printed on'
MK_DB_PRINT_END = '# Finished Make data base on'
DEFAULT_GOAL_PATTERN = re.compile(r'\.DEFAULT_GOAL[ \t]*.?=[ \t]*(?P<target>[a-zA-Z0-9\-_.]+)')
CONSIDERING_PATTERN = re.compile(r"(?P<indent>[ ]*)Considering target file '(?P<target>.*)'\.[ \t]*$")
MUST_REMAKE_PATTERN = re.compile(r"(?P<indent>[ ]*)Must remake target '(?P<target>.*)'\.[ \t]*$")
FINISH_PREREQ_PATTERN = re.compile(r"(?P<indent>[ ]*)Finished prerequisites of target file '(?P<target>.*)'\.[ \t]*$")
TARGET_REMADE_PATTER = re.compile(r"(?P<indent>[ ]*)Successfully remade target file '(?P<target>.*)'\.[ \t]*$")
NO_NEED_REMAKE_PATTERN = re.compile(r"(?P<indent>[ ]*)No need to remake target '(?P<target>[^']*)'[.;]")
SUB_MAKE_PATTERN = re.compile(r"^# GNU Make [34](\.[0-9]+)?[ \t]*$")
CURDIR_PATTERN = re.compile(r"^[ \t]*CURDIR[ \t]*:?=[ \t]*(?P<curdir>.*)$")
TARGET_FAILED_PATTERN = re.compile(r"recipe for target '(?P<target>.*)' failed")
MAKEFILE_PATTERN = re.compile(r"[ \t]*Reading makefile '(?P<makefile>.*)'\.\.\.[ \t]*$")
CMDGOALS_PATTERN = re.compile(r"^[ \t]*MAKECMDGOALS[ \t]*:?=[ \t]*(?P<cmdgoals>.*)$")
CONSIDERED_ALREADY_PATTERN = re.compile(r"[ \t]*File '(?P<target>.*)' was considered already.[ \t]*$")


class MakeInvocation(object):
    def __init__(self, level, parent, for_target):
        self.level = level  # submake level
        self.line_num = None
        self.targets = []  # top level targets considered for this invocation
        self.submakes = []  # top level submakes???
        self.database = None  # associated make database
        self.curdir = None  # working directory
        self.cmdgoals = None  # command line goals
        self.makefile = None  # associated makefile
        self.default_goal = None
        self.for_target = for_target  # for which target the make is invoked
        self.parent = parent  # parent make invocation
        self.current_target = None  # type: MakeTarget
        self.build_log = None
        self.db_start_pos = None
        self.db_end_pos = None

    def get_makefile(self):
        if not self.makefile:
            return "unknown makefile"
        if not self.curdir:
            curdir = '<curdir>'
        else:
            curdir = self.curdir
        if posixpath.isabs(self.makefile):
            return self.makefile
        return posixpath.join(curdir, self.makefile)


# MakeTarget state
MTST_CONSIDERING = 0x00
MTST_PREREQ_COLLECTING = 0x01
MTST_PREREQ_COLLECTED = 0x02
MTST_REMAKING = 0x03
MTST_UP_TO_DATE = 0x04
MTST_REMAKE_FAILED = 0x05
MTST_CONSIDERED_ALREADY = 0x06
MTST_REMADE = 0x07

MTST_NAMES = {
    MTST_CONSIDERING: "<considering>",
    MTST_PREREQ_COLLECTING: "<prereq collecting>",
    MTST_PREREQ_COLLECTED: "<prereq collected>",
    MTST_REMAKING: "<remaking>",
    MTST_UP_TO_DATE: "<up to date>",
    MTST_REMAKE_FAILED: "<failed>",
    MTST_CONSIDERED_ALREADY: "<considered already>",
    MTST_REMADE: "<updated>"
}


def get_make_target_state(mk):
    if isinstance(mk, MakeTarget) and \
            mk.state in MTST_NAMES:
        return MTST_NAMES[mk.state]
    return "<unknown>"


def get_line_number(line_no):
    if isinstance(line_no, int):
        return '{:,}'.format(line_no)
    else:
        return 'unknown'


INDENTION = '--'


class MakeTarget(object):
    def __init__(self, name, parent=None):
        self.name = name  # target name
        self.line_num = None
        self.parent = parent  # parent target if not top level
        self.submakes = []  # make invocations when making this target
        self.prereqs = []  # considered prereqs, instance of MakeTarget
        self.state = MTST_CONSIDERING
        self.invocation = None  # type: MakeInvocation
        self.failed_pos = None
        self.end_pos = None

    def dump(self, details='', indent=0, buffer=None, excludes=[]):
        for x in excludes:
            m = x.search(self.name)
            if m:
                return

        assert (isinstance(self.invocation, MakeInvocation))
        indent = self.invocation.level + indent
        indent = INDENTION * indent

        if not buffer:
            buffer = StringIO()
            logger = logging.getLogger('DUMP')
        else:
            logger = None

        buffer.write(indent)
        buffer.write('target <%s>, state %s\n' % (self.name, get_make_target_state(self)))
        if self.state == MTST_REMAKE_FAILED:
            buffer.write(indent + INDENTION)
            buffer.write('failed at line <%s>\n' % get_line_number(self.failed_pos))
        if 'v' in details:
            # line numbers
            buffer.write(indent + INDENTION)
            buffer.write('from: line <%s>, to: line <%s>\n' % (get_line_number(self.line_num),
                                                               get_line_number(self.end_pos)))
            buffer.write(indent + INDENTION)
            buffer.write('makefile: <%s>\n' % self.invocation.get_makefile())

            buffer.write(indent + INDENTION)
            buffer.write('make level: <%d>\n' % self.invocation.level)

            if 'vv' in details:
                buffer.write(indent + INDENTION)
                if self.parent:
                    buffer.write('parent: <%s>\n' % self.parent.name)
                else:
                    buffer.write('parent: NONE\n')

        # dump prerequisites
        if 'p' in details and self.prereqs:
            buffer.write(indent + INDENTION)
            buffer.write('prerequisites:\n')
            for prereq in self.prereqs:
                buffer.write(indent + 2 * INDENTION)
                buffer.write('<{}>\n'.format(prereq.name))

                if 'pp' in details and prereq.prereqs:
                    for pp in prereq.prereqs:
                        buffer.write(indent + 3 * INDENTION)
                        buffer.write('<{}>\n'.format(pp.name))

                        if 'ppp' in details and pp.prereqs:
                            for ppp in pp.prereqs:
                                buffer.write(indent + 4 * INDENTION)
                                buffer.write('<{}>\n'.format(pp.name))

        # dump submakes
        if 'm' in details and self.submakes:
            buffer.write(indent + INDENTION)
            buffer.write('submakes:\n')
            for submake in self.submakes:  # type: MakeInvocation
                buffer.write(indent + 2 * INDENTION)
                buffer.write('[{}]'.format(submake.get_makefile()))
                if submake.cmdgoals:
                    buffer.write(', command goals: <{}>'.format(submake.cmdgoals))
                elif submake.default_goal:
                    buffer.write(' , default goal: <{}>'.format(submake.default_goal))
                buffer.write('\n')

        if logger:
            logger.info(buffer.getvalue())


class TargetFilter(object):
    def __init__(self):
        self.name_pattern = None
        self.state_filter = None
        self.excludes = []


def build_log_scan(log_file):
    make_level = 0
    line_num = 0
    current_invocation = None  # type: MakeInvocation
    top_level_invocation = None
    logger = logging.getLogger('SCANNER')

    with open(log_file) as fp:
        for ln in fp:
            line_num += 1

            if isinstance(current_invocation, MakeInvocation) and \
               isinstance(current_invocation.database, StringIO):
                if current_invocation.db_start_pos is None:
                    current_invocation.db_start_pos = line_num

                current_invocation.database.write(ln)

                # <# Finished Make data base on>
                if ln.startswith(MK_DB_PRINT_END):
                    current_invocation.database.write(ln)
                    assert current_invocation.db_end_pos is None
                    current_invocation.db_end_pos = line_num
                    current_invocation.database = current_invocation.database.getvalue()

                    # update current make invocation
                    current_invocation = current_invocation.parent
                    make_level -= 1
                    continue

                # curdir extraction
                m = CURDIR_PATTERN.search(ln)
                if m:
                    curdir = m.group('curdir').strip()
                    assert (current_invocation.curdir is None)
                    current_invocation.curdir = curdir
                    continue

                # default goal extraction
                m = DEFAULT_GOAL_PATTERN.search(ln)
                if m:
                    default_goal = m.group('target').strip()
                    assert (current_invocation.default_goal is None)
                    current_invocation.default_goal = default_goal
                    continue

                # command line goal extraction
                m = CMDGOALS_PATTERN.search(ln)
                if m:
                    cmdgoals = m.group('cmdgoals').strip()
                    assert (current_invocation.cmdgoals is None)
                    current_invocation.cmdgoals = cmdgoals
                    continue

                continue

            # <# GNU Make 4.1>
            # a new "make" invocation
            m = SUB_MAKE_PATTERN.search(ln)
            if m:
                make_level += 1
                if isinstance(current_invocation, MakeInvocation):
                    for_target = current_invocation.current_target
                else:
                    for_target = None
                new_invocation = MakeInvocation(make_level, current_invocation, for_target)
                new_invocation.build_log = os.path.abspath(log_file)
                new_invocation.line_num = line_num
                if isinstance(for_target, MakeTarget):
                    for_target.submakes.append(new_invocation)
                elif isinstance(current_invocation, MakeInvocation):
                    current_invocation.submakes.append(new_invocation)
                current_invocation = new_invocation
                if top_level_invocation is None:
                    top_level_invocation = new_invocation

                if isinstance(for_target, MakeTarget):
                    logger.debug('new make invocation at line_number=%d, for target=%s, level=%d',
                                 line_num, for_target.name, make_level)
                else:
                    logger.debug('new make invocation at line_number=%d, level=%d',
                                 line_num, make_level)
                continue

            # makefile name
            if isinstance(current_invocation, MakeInvocation) and \
                    current_invocation.makefile is None:
                m = MAKEFILE_PATTERN.search(ln)
                if m:
                    makefile = m.group('makefile').strip()
                    current_invocation.makefile = makefile
                    continue

            # <Considering target file '...'>
            # a new target
            m = CONSIDERING_PATTERN.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        len(target_name) > 0)
                new_target = MakeTarget(target_name, current_invocation.current_target)
                new_target.line_num = line_num
                new_target.invocation = current_invocation
                if isinstance(current_invocation.current_target, MakeTarget):
                    current_invocation.current_target.prereqs.append(new_target)
                    current_invocation.current_target.state = MTST_PREREQ_COLLECTING
                    logger.debug('new make target name=<%s>, as prereq for target=<%s>, line_number=%d',
                                 target_name, current_invocation.current_target.name, line_num)
                else:
                    current_invocation.targets.append(new_target)
                    logger.debug('new make target name=<%s>, line_number=%d',
                                 target_name, line_num)
                current_invocation.current_target = new_target
                continue

            m = CONSIDERED_ALREADY_PATTERN.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        isinstance(current_invocation.current_target, MakeTarget) and \
                        current_invocation.current_target.state == MTST_CONSIDERING and \
                        current_invocation.current_target.name == target_name)
                current_invocation.current_target.state = MTST_CONSIDERED_ALREADY
                current_invocation.current_target.end_pos = line_num
                current_invocation.current_target = current_invocation.current_target.parent
                continue

            # <Finished prerequisites of target file '...'>
            # prerequisites analysis completes
            m = FINISH_PREREQ_PATTERN.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        isinstance(current_invocation.current_target, MakeTarget) and \
                        target_name == current_invocation.current_target.name and \
                        current_invocation.current_target.state in [MTST_CONSIDERING, MTST_PREREQ_COLLECTING])
                current_invocation.current_target.state = MTST_PREREQ_COLLECTED
                logger.debug('target <%s> prerequisites collected, line_number=%d',
                             target_name, line_num)
                continue

            # <Must remake target '...'>
            # must remake target
            m = MUST_REMAKE_PATTERN.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        isinstance(current_invocation.current_target, MakeTarget) and \
                        target_name == current_invocation.current_target.name and \
                        current_invocation.current_target.state == MTST_PREREQ_COLLECTED)
                current_invocation.current_target.state = MTST_REMAKING
                logger.debug('target <%s> need remade, line_number=%d',
                             target_name, line_num)
                continue

            # <No need to remake target '...'>
            # no need to remake
            m = NO_NEED_REMAKE_PATTERN.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        isinstance(current_invocation.current_target, MakeTarget) and \
                        target_name == current_invocation.current_target.name and \
                        current_invocation.current_target.state == MTST_PREREQ_COLLECTED)
                current_invocation.current_target.state = MTST_UP_TO_DATE
                logger.debug('target <%s> no need to remake, line_number=%d',
                             target_name, line_num)
                # update current target
                current_invocation.current_target.end_pos = line_num
                current_invocation.current_target = current_invocation.current_target.parent
                continue

            # <Successfully remade target file '...'>
            # target remade successfully
            m = TARGET_REMADE_PATTER.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        isinstance(current_invocation.current_target, MakeTarget) and \
                        target_name == current_invocation.current_target.name and \
                        current_invocation.current_target.state in [MTST_REMAKING, MTST_REMAKE_FAILED])
                current_invocation.current_target.state = MTST_REMADE
                logger.debug('target <%s> remade successfully, line_number=%d',
                             target_name, line_num)
                # update current target
                current_invocation.current_target.end_pos = line_num
                current_invocation.current_target = current_invocation.current_target.parent
                continue

            # <recipe for target '...' failed>
            # target failed
            m = TARGET_FAILED_PATTERN.search(ln)
            if m:
                target_name = m.group('target').strip()
                assert (isinstance(current_invocation, MakeInvocation) and \
                        isinstance(current_invocation.current_target, MakeTarget))

                if target_name != current_invocation.current_target.name:
                    continue

                assert (current_invocation.current_target.state in [MTST_REMAKING, MTST_REMAKE_FAILED])
                current_invocation.current_target.state = MTST_REMAKE_FAILED
                current_invocation.current_target.failed_pos = line_num
                current_invocation.current_target.end_pos = line_num
                # postpone current target update
                logger.debug('recipe failed for target <%s>, line_number=%d',
                             target_name, line_num)
                continue

            # <# Make data base, printed on ...>
            if ln.startswith(MK_DB_PRINT_BEGIN):
                assert (isinstance(current_invocation, MakeInvocation) and \
                        current_invocation.database is None)
                current_invocation.database = StringIO()
                current_invocation.database.write(ln)
                logger.debug('start collecting make database, line_number=%d',
                             line_num)
                # update current target
                if isinstance(current_invocation.current_target, MakeTarget) and \
                        current_invocation.current_target.state == MTST_REMAKE_FAILED:
                    current_invocation.current_target = current_invocation.current_target.parent
                continue

    assert (current_invocation is None and \
            make_level == 0)
    return top_level_invocation


def load_make_database(mkdb_file):
    with open(mkdb_file, 'rb') as fp:
        return pickle.load(fp)


def save_make_database(mkdb_file, mkdb):
    assert (isinstance(mkdb, MakeInvocation))
    with open(mkdb_file, 'wb') as fp:
        pickle.dump(mkdb, fp)


def find_target(mkdb, filter: TargetFilter):
    if isinstance(mkdb, MakeInvocation):
        for target in mkdb.targets:
            yield from find_target(target, filter)
        for submake in mkdb.submakes:
            yield from find_target(submake, filter)
    elif isinstance(mkdb, MakeTarget):
        if mkdb.name.find('apps') >= 0:
            pause = 1
        discard = False
        if filter.name_pattern is not None:
            m = filter.name_pattern.search(mkdb.name)
            if not m:
                discard = True

        if not discard and filter.state_filter is not None:
            if mkdb.state == filter.state_filter:
                pass
            elif isinstance(filter.state_filter, (list, set)) and \
                    mkdb.state in filter.state_filter:
                pass
            else:
                discard = True

        if filter.excludes:
            for x in filter.excludes:
                m = x.search(mkdb.name)
                if m:
                    discard = True
                    break

        if not discard:
            yield mkdb

        for prereq in mkdb.prereqs:
            yield from find_target(prereq, filter)
        for submake in mkdb.submakes:
            yield from find_target(submake, filter)
    else:
        raise RuntimeError('invalid parameter')


VERBOSE_LEVEL = {
    'critical': logging.CRITICAL,
    'fatal': logging.FATAL,
    'error': logging.ERROR,
    'warning': logging.WARNING,
    'info': logging.INFO,
    'debug': logging.DEBUG
}
DEFAULT_VERBOSE_LEVEL = logging.INFO

NAME_TO_TARGET_STATE = {
    "succeed": MTST_REMADE,
    "failed": MTST_REMAKE_FAILED,
    "up_to_date": MTST_UP_TO_DATE
}


class LogWithIndent(logging.Formatter):
    def format(self, record):
        s = super().format(record)
        lines = s.splitlines(keepends=True)
        buffer = StringIO()
        idx = 0
        for ln in lines:
            if idx == 0:
                buffer.write(ln)
            else:
                buffer.write(INDENTION + ln)
            idx += 1
        return buffer.getvalue()


def init_logging(verbose):
    formatter = LogWithIndent(fmt='[%(name)s - %(levelname)s]\n%(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logging.basicConfig(level=verbose, handlers=[handler])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-S', '--save', default=None)
    parser.add_argument('-L', '--load', default=None)
    parser.add_argument('-t', '--target', default=None)
    parser.add_argument('-s', '--state', default=None)
    parser.add_argument('-l', '--log', default=None)
    parser.add_argument('-v', '--verbose', default=None)
    parser.add_argument('-d', '--details', default='d')
    parser.add_argument('-x', '--exclude', action='append', default=None)

    options, args = parser.parse_known_args(sys.argv)

    # set up default output level
    if options.verbose in VERBOSE_LEVEL:
        verbose_level = VERBOSE_LEVEL[options.verbose]
    else:
        try:
            verbose_level = int(options.verbose)
        except (ValueError, TypeError):
            verbose_level = DEFAULT_VERBOSE_LEVEL
    init_logging(verbose_level)

    logger = logging.getLogger('APP')
    if options.log:
        mk = build_log_scan(options.log)
    elif options.load:
        mk = load_make_database(options.load)
    else:
        logger.error('no make database file specified')
        sys.exit(-1)

    if options.save:
        save_make_database(options.save, mk)
        logger.info('make database saved to file <%s>', options.save)
        sys.exit(0)

    target_filter = None
    if options.target:
        logger.info('target name regexp: <{}>'.format(options.target))

        target_filter = TargetFilter()
        target_filter.name_pattern = re.compile(options.target)

    if options.state:
        state_filter = set([])
        words = options.state.strip().split()
        for w in words:
            if w in NAME_TO_TARGET_STATE:
                state_filter.add(NAME_TO_TARGET_STATE[w])
        if state_filter:
            if not target_filter:
                target_filter = TargetFilter()
            target_filter.state_filter = state_filter

    if options.exclude:
        if not target_filter:
            target_filter = TargetFilter()

        for x in options.exclude:
            target_filter.excludes.append(re.compile(x))

    if target_filter:
        for mk_target in find_target(mk, target_filter):
            mk_target.dump(details=options.details, indent=-mk_target.invocation.level,
                           excludes=target_filter.excludes)


if __name__ == '__main__':
    main()
