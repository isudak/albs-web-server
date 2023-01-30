from fastapi import status
import pytest
import httpx

from alws.app import app
from alws.config import settings

from alws.dependencies import get_db
from alws.utils import jwt_utils
from tests.conftest import get_session
from tests.constants import ADMIN_USER_ID


@pytest.mark.anyio
class BaseAsyncTestCase:
    user_id: int = ADMIN_USER_ID
    token: str = ""
    headers: dict = {}
    status_codes = status

    async def make_request(
        self,
        method: str,
        endpoint: str,
        headers: dict = None,
        json: dict = None,
    ):
        if not headers:
            headers = {}
        headers.update(self.headers)
        async with httpx.AsyncClient(
            app=app,
            base_url="http://localhost:8080",
        ) as client:
            http_method = getattr(client, method)
            return await http_method(
                endpoint,
                headers=headers,
                json=json,
            )

    @classmethod
    def setup_class(cls):
        app.dependency_overrides[get_db] = get_session
        cls.token = jwt_utils.generate_JWT_token(
            str(cls.user_id),
            settings.jwt_secret,
            "HS256",
        )
        cls.headers.update(
            {
                "Authorization": f"Bearer {cls.token}",
            }
        )