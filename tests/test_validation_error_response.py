"""A 422 names the field and says what is wrong with it, and never repeats what was sent.

The framework's default 422 returned every rejected value ("input"), so a password typed into the
sign-in form's username field came straight back in the response, and a large rejected body was
serialized a second time on the event loop. These check the helper that shapes the errors and that
the application answers every validation failure through it.
"""
import json

import pytest
from pydantic import BaseModel, Field, ValidationError

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from app.core.validation_errors import MAX_ERRORS, MAX_LOC_PART, MAX_MESSAGE, public_validation_errors

pytestmark = pytest.mark.unit

SECRET = "correct-horse-battery-staple-7731"


def _app():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _login_errors(body):
    """The errors the sign-in route's own body model reports for `body`, as the framework sees them."""
    S = _app()
    from fastapi.exceptions import RequestValidationError
    try:
        S.LoginRequest.model_validate(body)
    except ValidationError as exc:
        return RequestValidationError(
            [dict(e, loc=("body",) + tuple(e["loc"])) for e in exc.errors(include_url=False)])
    raise AssertionError("the body was valid")


def test_the_errors_keep_type_location_and_message_and_nothing_else():
    errors = [{"type": "string_too_long", "loc": ("body", "username"),
               "msg": "String should have at most 254 characters", "input": SECRET * 20,
               "ctx": {"max_length": 254}, "url": "https://errors.pydantic.dev/x"}]
    assert public_validation_errors(errors) == [
        {"type": "string_too_long", "loc": ["body", "username"],
         "msg": "String should have at most 254 characters"}]


def test_a_validator_exception_in_the_context_is_dropped():
    class M(BaseModel):
        pin: str = Field(pattern=r"^\d{4}$")

    try:
        M(pin=SECRET)
    except ValidationError as exc:
        out = public_validation_errors(exc.errors())
    assert SECRET not in json.dumps(out)
    assert out[0]["loc"] == ["pin"] and out[0]["msg"]


def test_the_count_a_location_part_and_a_message_are_bounded():
    many = [{"type": "missing", "loc": ("body", i), "msg": "Field required"} for i in range(5000)]
    out = public_validation_errors(many)
    assert len(out) == MAX_ERRORS and out[0]["loc"] == ["body", 0]
    long_key = "k" * 10_000
    out = public_validation_errors([{"type": "extra_forbidden", "loc": ("body", long_key),
                                     "msg": "m" * 10_000}])
    assert len(out[0]["loc"][1]) <= MAX_LOC_PART + 3 and len(out[0]["msg"]) <= MAX_MESSAGE + 3


def test_the_application_answers_a_422_without_the_password_typed_into_the_username():
    S = _app()
    from fastapi.exceptions import RequestValidationError
    handler = S.app.exception_handlers.get(RequestValidationError)
    assert handler is S._request_validation_error_handler, "422s are not answered through the helper"
    exc = _login_errors({"username": SECRET + "x" * 300, "password": "x"})
    response = run_coroutine(handler(None, exc))
    assert response.status_code == 422
    text = response.body.decode()
    assert SECRET not in text, "the 422 repeated what was typed into the username field"
    detail = json.loads(text)["detail"]
    assert detail and detail[0]["loc"] == ["body", "username"] and "254" in detail[0]["msg"]
    assert all(set(e) == {"type", "loc", "msg"} for e in detail)
