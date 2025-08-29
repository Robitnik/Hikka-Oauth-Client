from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional
from urllib.parse import urlparse, parse_qs

import requests


# --------------------------
# Модель third-party токена від Hikka
# --------------------------
@dataclass
class HikkaToken:
    """
    Секрет для звернень до Hikka від імені користувача.
    Використовується як:  Header  Auth: <secret>
    """
    secret: str
    token_reference: Optional[str] = None  # може знадобитись для відкликання
    expires_in: int = 0
    scope: Optional[str] = None
    obtained_at: float = 0.0

    @property
    def expires_at(self) -> float:
        return (self.obtained_at or 0) + (self.expires_in or 0)

    def is_expired(self, skew: int = 30) -> bool:
        """True, якщо токен прострочений (з урахуванням безпечного зсуву, сек)."""
        return time.time() >= (self.expires_at - max(0, skew))


class HikkaOAuthError(RuntimeError):
    pass


class HikkaOAuthClient:
    """
    Клієнт для інтеграції твого застосунку з Hikka (third-party).

    Потік:
      1) build_authorize_url(client_reference, ...) → редіректимо користувача на Hikka.
      2) Hikka після згоди редіректить на твій redirect_uri з параметром `reference`
         (це ж саме, що `request_reference`).
      3) exchange_request_reference(reference) → отримуємо секрет (HikkaToken.secret).
      4) get_current_user(secret=...) → читаємо профіль користувача.
      5) (опційно) revoke_token(token_reference=...) → відкликаємо токен.
    """

    AUTH_BASE = "https://hikka.io"        # фронтовий домен для згоди
    API_BASE = "https://api.hikka.io"     # серверні API

    # Ендпоінти
    AUTHORIZE_PATH = "/oauth"                                 # GET hikka.io/oauth?... (Hikka сама згенерує reference)
    TOKEN_CREATE_PATH = "/auth/token"                         # POST api.hikka.io/auth/token
    TOKEN_INFO_PATH = "/auth/token/info"                      # GET  api.hikka.io/auth/token/info
    TOKEN_REVOKE_PATH = "/auth/token/{token_reference}"       # DELETE api.hikka.io/auth/token/{token_reference}
    ME_PATH = "/user/me"                                      # GET  api.hikka.io/user/me  (Auth: <secret>)

    def __init__(
        self,
        
        client_reference: str,                 # ідентифікатор твого клієнта в Hikka
        client_secret: str,                    # секрет твого клієнта
        auth_base: Optional[str] = None,
        api_base: Optional[str] = None,
        session: Optional[requests.Session] = None,
        timeout: float = 15.0,
    ) -> None:
        self.client_reference = client_reference
        self.client_secret = client_secret
        self.auth_base = (auth_base or self.AUTH_BASE).rstrip("/")
        self.api_base = (api_base or self.API_BASE).rstrip("/")
        self.http = session or requests.Session()
        self.timeout = timeout

    # --------------------------
    # 1) Побудувати URL згоди
    # --------------------------
    def build_authorize_url(
        self,
        
        scopes: Optional[Iterable[str]] = None,
    ) -> str:
        """
        Формує посилання на сторінку згоди Hikka.
        Hikka сама згенерує request_reference та поверне його у ?reference=... на redirect_uri.
        """
        base = f"{self.auth_base}{self.AUTHORIZE_PATH}"
        params = {
            "reference": self.client_reference,
        }
        if scopes:
            params["scope"] = ",".join(scopes)
        return f"{base}?{urllib.parse.urlencode(params)}"

    # --------------------------
    # 2) Обміняти request_reference на секрет
    # --------------------------
    def exchange_request_reference(
        self,
        
        request_reference: str,
        extra: Optional[Mapping[str, object]] = None,
    ) -> HikkaToken:
        """
        POST /auth/token
        Тіло: { "request_reference": "...", "client_secret": "..." }
        Повертає секрет, яким підписуються подальші запити (заголовок Auth).
        """
        url = f"{self.api_base}{self.TOKEN_CREATE_PATH}"
        payload: Dict[str, object] = {
            "request_reference": request_reference,
            "client_secret": self.client_secret,
        }
        if extra:
            payload.update(extra)

        r = self.http.post(url, json=payload, timeout=self.timeout)
        if r.status_code >= 400:
            raise HikkaOAuthError(
                f"exchange_request_reference не вдалося [{r.status_code}]: {r.text}"
            )
        return self._parse_token_create_response(r.json())

    # --------------------------
    # 3) Отримати профіль поточного користувача
    # --------------------------
    def get_current_user(self,  secret: str) -> Mapping[str, object]:
        """
        GET /user/me  з заголовком  Auth: <secret>
        """
        url = f"{self.api_base}{self.ME_PATH}"
        r = self.http.get(url, headers={"Auth": secret}, timeout=self.timeout)
        if r.status_code >= 400:
            raise HikkaOAuthError(f"/user/me не вдалося [{r.status_code}]: {r.text}")
        return r.json()

    # --------------------------
    # Додатково: інфо про токен / відкликання
    # --------------------------
    def get_token_info(self,  secret: str) -> Mapping[str, object]:
        url = f"{self.api_base}{self.TOKEN_INFO_PATH}"
        r = self.http.get(url, headers={"Auth": secret}, timeout=self.timeout)
        if r.status_code >= 400:
            raise HikkaOAuthError(
                f"/auth/token/info не вдалося [{r.status_code}]: {r.text}"
            )
        return r.json()

    def revoke_token(self,  token_reference: str) -> None:
        url = f"{self.api_base}{self.TOKEN_REVOKE_PATH.format(token_reference=token_reference)}"
        r = self.http.delete(url, timeout=self.timeout)
        if r.status_code >= 400:
            raise HikkaOAuthError(
                f"Відкликання токена не вдалося [{r.status_code}]: {r.text}"
            )

    # --------------------------
    # Утиліти
    # --------------------------
    @staticmethod
    def extract_reference_from_redirect(redirect_url: str) -> Optional[str]:
        """
        Дістати request_reference з URL редіректу (шукаємо 'reference' або 'request_reference').
        """
        q = parse_qs(urlparse(redirect_url).query)
        return (
            (q.get("reference") or q.get("request_reference") or [None])[0]
        )

    @staticmethod
    def _parse_token_create_response(data: Mapping[str, object]) -> HikkaToken:
        """
        Очікуємо принаймні поле 'secret'. Деякі інсталяції можуть повертати також:
        'token_reference', 'expires_in', 'scope'.
        """
        secret = data.get("secret") or data.get("access_token") or data.get("token")
        if not secret:
            raise HikkaOAuthError(f"Неочікувана відповідь від /auth/token: {data}")
        return HikkaToken(
            secret=str(secret),
            token_reference=(data.get("token_reference") or data.get("reference") or None),
            expires_in=int(data.get("expires_in") or 0),
            scope=(data.get("scope") or None),
            obtained_at=time.time(),
        )
