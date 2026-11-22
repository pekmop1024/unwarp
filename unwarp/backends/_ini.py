"""Edit selected settings in single-peer exports while preserving unrelated lines."""


class Section:
    def __init__(self, text: str, name: str, *, case_sensitive=True):
        self.lines = text.splitlines(keepends=True)
        self.name = name
        self.case_sensitive = case_sensitive
        start = None
        end = len(self.lines)
        for index, line in enumerate(self.lines):
            heading = line.partition('#')[0].strip()
            if not (heading.startswith('[') and heading.endswith(']')):
                continue
            if start is not None and end == len(self.lines):
                end = index
            if self._matches(heading, f'[{name}]'):
                if start is not None:
                    raise ValueError(f'expected a single [{name}] section in the profile')
                start = index + 1
        if start is None:
            raise ValueError(f'missing [{name}] section in the profile')
        self.start, self.end = start, end

    def _matches(self, value, expected):
        return value == expected if self.case_sensitive else value.lower() == expected.lower()

    def _settings(self, key):
        for index in range(self.start, self.end):
            field, separator, value = self.lines[index].partition('=')
            if separator and self._matches(field.strip(), key):
                value = value.partition('#')[0].strip()
                if value.endswith('\\'):
                    raise ValueError(f'cannot update a continued {key} setting in [{self.name}]')
                yield index, value

    def values(self, key: str, *, reset_empty=False) -> list[str]:
        values = []
        for _, value in self._settings(key):
            if reset_empty and not value:
                values.clear()
            else:
                values.append(value)
        return values

    def set(self, key: str, value: str) -> str:
        """Replace repeated settings with one line, omitting empty values."""
        entries = list(self._settings(key))
        if [v for _, v in entries] == ([value] if value else []):
            return ''.join(self.lines)
        lines = self.lines.copy()
        index = entries[0][0] if entries else self.start
        for old, _ in reversed(entries):
            del lines[old]
        if value:
            lines.insert(index, f'{key}={value}\n')
        return ''.join(lines)
