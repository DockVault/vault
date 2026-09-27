"""A stand-in database session that holds rows in memory and really applies the filters it is given.

For unit tests that must show what a query *does*, not what its text says: which rows a filter keeps,
which rows an UPDATE changes, which rows a DELETE removes. A recording fake that returns canned
results cannot fail when a filter is dropped from a query; this one can, because it evaluates the
SQLAlchemy criteria the code under test builds against the rows it holds, the way the database would
for the small set of expressions these paths use: comparisons, IS [NOT] NULL, IN (a list or a
``select()``), AND, OR, true/false, with SQL's three-valued logic.

Rows are plain objects (``types.SimpleNamespace`` is enough) filed under their model class::

    db = MemoryDB({File: [f1, f2], Vault: [v1]})
    db.query(File).filter(File.vault_id == v1.id, file_expiry.live_clause()).all()

A query for columns (``db.query(File.id, File.size_bytes)``) returns rows that unpack like tuples
and read like objects. ``with_for_update`` is recorded in ``db.log``; with ``skip_locked=True`` it
skips the rows whose id is in ``db.held`` (locked by someone else). Anything this does not model
raises, so a test never passes by accident on an expression it silently ignored.
"""
import operator

from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.sql import elements, operators
from sqlalchemy.sql.selectable import ScalarSelect, Select

_COMPARE = {
    operators.eq: operator.eq, operators.ne: operator.ne,
    operators.gt: operator.gt, operators.ge: operator.ge,
    operators.lt: operator.lt, operators.le: operator.le,
}


class _Row(tuple):
    """A column query's row: unpacks like a tuple, reads like an object."""

    def __new__(cls, keys, values):
        row = super().__new__(cls, values)
        row._keys = keys
        return row

    def __getattr__(self, name):
        try:
            return self[self._keys.index(name)]
        except ValueError:
            raise AttributeError(name) from None


class MemoryDB:
    def __init__(self, tables=None):
        self.tables = {model: list(rows) for model, rows in (tables or {}).items()}
        self.held = set()        # ids another session holds locked
        self.log = []            # ("lock", model, kw) / ("update", model, n) / ("delete", model, n) / ...
        self.on_lock = []        # callables run once, in order, before the next locking read
        self.added, self.deleted = [], []

    # -- the session surface the code under test uses ---------------------------------------
    def query(self, *entities):
        return MemoryQuery(self, entities)

    def add(self, obj):
        self.added.append(obj)
        self.log.append(("add", obj))

    def delete(self, obj):
        for rows in self.tables.values():
            if obj in rows:
                rows.remove(obj)
        self.deleted.append(obj)
        self.log.append(("orm-delete", obj))

    def flush(self):
        self.log.append(("flush",))

    def commit(self):
        self.log.append(("commit",))

    def rollback(self):
        self.log.append(("rollback",))

    def refresh(self, obj):
        pass

    # -- evaluation ---------------------------------------------------------------------------
    def rows_of(self, model):
        return self.tables.setdefault(model, [])

    def model_of_table(self, table):
        for model in self.tables:
            if getattr(model, "__table__", None) is table:
                return model
        raise AssertionError(f"no rows are held for table {table.name!r}")

    def value(self, expr, row):
        """The value of one side of a comparison for `row`."""
        if isinstance(expr, InstrumentedAttribute):
            expr = expr.expression
        if isinstance(expr, elements.Grouping):
            return self.value(expr.element, row)
        if isinstance(expr, elements.BindParameter):
            return expr.effective_value
        if isinstance(expr, elements.Null):
            return None
        if isinstance(expr, elements.True_):
            return True
        if isinstance(expr, elements.False_):
            return False
        if isinstance(expr, ScalarSelect):
            expr = expr.element
        if isinstance(expr, Select):
            return self.select_values(expr)
        if isinstance(expr, elements.ColumnClause) and getattr(expr, "table", None) is not None:
            return getattr(row, expr.key)
        raise AssertionError(f"MemoryDB does not model the expression {expr!r}")

    def select_values(self, stmt):
        (column,) = stmt.selected_columns
        model = self.model_of_table(column.table)
        rows = [r for r in self.rows_of(model)
                if stmt.whereclause is None or self.truth(stmt.whereclause, r) is True]
        return [getattr(r, column.key) for r in rows]

    def truth(self, clause, row):
        """SQL truth of `clause` for `row`: True, False or None (unknown)."""
        if isinstance(clause, elements.Grouping):
            return self.truth(clause.element, row)
        if isinstance(clause, elements.True_):
            return True
        if isinstance(clause, elements.False_):
            return False
        if isinstance(clause, elements.BooleanClauseList):
            vals = [self.truth(c, row) for c in clause.clauses]
            if clause.operator is operators.and_:
                return False if False in vals else (None if None in vals else True)
            if clause.operator is operators.or_:
                return True if True in vals else (None if None in vals else False)
        if isinstance(clause, elements.BinaryExpression):
            op = clause.operator
            left = self.value(clause.left, row)
            right = self.value(clause.right, row)
            if op is operators.is_:
                return left is right if isinstance(right, bool) else left is None
            if op is operators.is_not:
                return left is not right if isinstance(right, bool) else left is not None
            if op in (operators.in_op, operators.not_in_op):
                if left is None:
                    return None
                found = left in list(right)
                return found if op is operators.in_op else not found
            if op in _COMPARE:
                if left is None or right is None:
                    return None
                return _COMPARE[op](left, right)
        raise AssertionError(f"MemoryDB does not model the clause {clause!r}")


class MemoryQuery:
    def __init__(self, db, entities):
        self.db, self.entities = db, entities
        self.criteria, self.order, self.lock, self.limit_n, self.unique = [], [], None, None, False
        first = entities[0]
        self.model = first if isinstance(first, type) else first.class_
        self.columns = None if isinstance(first, type) else [e.key for e in entities]

    def filter(self, *criteria):
        self.criteria.extend(criteria)
        return self

    def order_by(self, *cols):
        self.order.extend(cols)
        return self

    def with_for_update(self, **kw):
        self.lock = kw
        return self

    def populate_existing(self):
        return self

    def distinct(self):
        self.unique = True
        return self

    def limit(self, n):
        self.limit_n = n
        return self

    def offset(self, n):
        self.offset_n = n
        return self

    def _matching(self):
        if self.lock is not None:
            self.db.log.append(("lock", self.model, dict(self.lock)))
            while self.db.on_lock:
                self.db.on_lock.pop(0)()
        rows = [r for r in self.db.rows_of(self.model)
                if all(self.db.truth(c, r) is True for c in self.criteria)]
        if self.lock is not None and self.lock.get("skip_locked"):
            rows = [r for r in rows if getattr(r, "id", None) not in self.db.held]
        for col in reversed(self.order):
            desc = isinstance(col, elements.UnaryExpression) and col.modifier is operators.desc_op
            key = (col.element if isinstance(col, elements.UnaryExpression) else col).key
            rows.sort(key=lambda r: getattr(r, key), reverse=desc)
        return rows

    def _shape(self, rows):
        if self.columns is None:
            out = rows
        else:
            out = [_Row(self.columns, [getattr(r, k) for k in self.columns]) for r in rows]
            if self.unique:
                out = list(dict.fromkeys(out))
        out = out[getattr(self, "offset_n", 0) or 0:]
        return out[:self.limit_n] if self.limit_n is not None else out

    def all(self):
        return self._shape(self._matching())

    def first(self):
        rows = self.all()
        return rows[0] if rows else None

    def scalar(self):
        row = self.first()
        return None if row is None else (row[0] if self.columns else row)

    def count(self):
        return len(self._matching())

    def update(self, values, synchronize_session=None):
        rows = self._matching()
        for r in rows:
            for col, new in values.items():
                key = (col.key if hasattr(col, "key") else col)
                if isinstance(new, InstrumentedAttribute):
                    new = getattr(r, new.key)          # col = col: left as it is
                setattr(r, key, new)
        self.db.log.append(("update", self.model, len(rows)))
        return len(rows)

    def delete(self, synchronize_session=None):
        rows = self._matching()
        table = self.db.rows_of(self.model)
        for r in rows:
            table.remove(r)
        self.db.log.append(("delete", self.model, len(rows)))
        return len(rows)
