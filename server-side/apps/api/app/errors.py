import logging

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger('backend_api.errors')


class DatabaseUnavailableError(Exception):
    pass


def register_exception_handlers(app) -> None:
    @app.exception_handler(DatabaseUnavailableError)
    async def database_unavailable_handler(request: Request, exc: DatabaseUnavailableError):
        return JSONResponse(status_code=503, content={'detail': 'Database temporarily unavailable'})

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={'detail': exc.errors()})

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.detail})

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, 'request_id', '-')
        logger.exception('Unhandled exception request_id=%s path=%s', request_id, request.url.path)
        return JSONResponse(status_code=500, content={'detail': 'Internal server error'})
