"""Validate and rewrite the only data accepted from coverage execution."""

from dataclasses import dataclass
import re
from xml.etree import ElementTree as XML

from sonar_exec import PublishError


REPORT_LIMIT = 500_000
REPORT_HEADER = b'OC-COVERAGE-XML\n'
CONDITION = re.compile(r'[0-9]{1,3}% \(([0-9]{1,3})/([0-9]{1,3})\)')


@dataclass(frozen=True)
class Coverage:
    xml: bytes
    metrics: dict


def canonical_report(output, source, cores):
    if not output.startswith(REPORT_HEADER) or len(output) > REPORT_LIMIT:
        raise PublishError('Coverage output has missing framing or exceeds the report limit')
    raw = output[len(REPORT_HEADER):].decode('utf-8')
    if '<!DOCTYPE' in raw or '<!ENTITY' in raw:
        raise PublishError('Coverage XML contains a forbidden declaration')
    try:
        tree = XML.fromstring(raw)
    except XML.ParseError as error:
        raise PublishError('Coverage XML is malformed') from error
    entries = tree.findall('./packages/package/classes/class')
    if (tree.tag != 'coverage' or len(entries) != len(cores)
            or {entry.get('filename') for entry in entries} != set(cores)):
        raise PublishError('Coverage XML does not contain exactly the required core files')
    report = XML.Element('coverage')
    XML.SubElement(XML.SubElement(report, 'sources'), 'source').text = '.'
    classes = XML.SubElement(XML.SubElement(XML.SubElement(report, 'packages'), 'package'), 'classes')
    metrics = {}
    for entry in sorted(entries, key=lambda item: item.get('filename')):
        filename = entry.attrib['filename']
        line_limit = len((source / filename).read_bytes().splitlines())
        lines = XML.SubElement(XML.SubElement(classes, 'class', filename=filename), 'lines')
        metrics[filename] = canonical_lines(entry, lines, line_limit)
    return Coverage(XML.tostring(report, encoding='utf-8', xml_declaration=True), metrics)


def canonical_lines(entry, destination, line_limit):
    counts = dict(lines_to_cover=0, uncovered_lines=0, conditions_to_cover=0, uncovered_conditions=0)
    previous = 0
    for line in entry.findall('./lines/line'):
        number, hits = line.get('number', ''), line.get('hits')
        if not re.fullmatch(r'[0-9]{1,8}', number) or not previous < int(number) <= line_limit or hits not in ('0', '1'):
            raise PublishError('Coverage XML has invalid or duplicate line data')
        previous = int(number)
        attrs = dict(number=str(previous), hits=hits)
        counts['lines_to_cover'] += 1
        counts['uncovered_lines'] += hits == '0'
        if line.get('branch') == 'true':
            condition = CONDITION.fullmatch(line.get('condition-coverage', ''))
            if not condition:
                raise PublishError('Coverage XML has invalid branch data')
            covered, total = map(int, condition.groups())
            if not 0 <= covered <= total <= 255 or total == 0 or (hits == '0' and covered):
                raise PublishError('Coverage XML has inconsistent branch counts')
            counts['conditions_to_cover'] += total
            counts['uncovered_conditions'] += total - covered
            attrs.update(branch='true', **{'condition-coverage': f'{covered * 100 // total}% ({covered}/{total})'})
        XML.SubElement(destination, 'line', attrs)
    if not counts['lines_to_cover'] or not counts['conditions_to_cover']:
        raise PublishError('A required core has no line or branch coverage data')
    return counts
