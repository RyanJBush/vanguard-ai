from sqlalchemy.orm import Query


def paginate_query(query: Query, *, page: int, page_size: int):
    safe_page = max(page, 1)
    safe_page_size = max(min(page_size, 200), 1)
    total = query.count()
    items = query.offset((safe_page - 1) * safe_page_size).limit(safe_page_size).all()
    return items, total, safe_page, safe_page_size
