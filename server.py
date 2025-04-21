import os

from aiohttp.web_exceptions import HTTPNotFound
from aiohttp.web_middlewares import middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from sqlalchemy.exc import IntegrityError
from models import Advertisement, Session, User, init_orm, close_orm
from auth import check_password
from sqlalchemy import select
import json
from aiohttp import web
from aiohttp_auth import auth
from aiohttp_security import authorized_userid, remember, setup
from aiohttp_session import session_middleware

secret_key = os.urandom(32)
session_storage = EncryptedCookieStorage(secret_key)
policy = auth.SessionTktAuthentication(secret_key, 60, include_ip=True)
middlewares = [
    session_middleware(session_storage),
    auth.auth_middleware(policy)
]
app = web.Application(middlewares=middlewares)

setup(app, SessionIdentityPolicy(), )

async def orm_context(app: web.Application):
    await init_orm()
    yield
    await close_orm()


@middleware
async def session_middleware(request: web.Request, handler):
    async with Session() as session:
        request.session = session
        response = await handler(request)

        return response


def generate_error(err_cls, message: str):
    message = json.dumps({"error": message})
    return err_cls(text=message, content_type="application/json")


async def login(request):
    session = Session()
    json_data = await request.json()
    query = await session.execute(select(User).filter_by(email=json_data['email']))
    user = query.scalars().first()
    if user and check_password(json_data['password'], user.password):
        await remember(request, user.id_dict, user.get_id())
        return web.json_response({"message": "Logged in successfully"}, content_type='application/json')
    return web.json_response({"error": "Invalid credentials"}, content_type='application/json')

async def get_advertisement_by_id(adv_id: int, session) -> Advertisement:
    advertisement = await session.get(Advertisement, adv_id)
    if advertisement is None:
        raise generate_error(HTTPNotFound, "advertisement not found")
    return advertisement


async def add_advertisement(advertisement: Advertisement, session):
    try:
        session.add(advertisement)
        await session.commit()
    except IntegrityError:
        raise generate_error(web.HTTPConflict, "advertisement already exists")

async def delete_advertisement(advertisement: Advertisement, session):
    session.delete(advertisement)
    await session.commit()

async def get_current_user(request):
    user_id = await authorized_userid(request)
    return user_id

class AdvertisementView(web.View):
    @property
    def session(self):
        return self.request.session

    @property
    def adv_id(self):
        return int(self.request.match_info["id"])


    async def get_current_advertisement(self):
        advertisement = await get_advertisement_by_id(self.adv_id, self.session)


    async def get(self):
        advertisement = await self.get_current_advertisement()
        return web.json_response(advertisement.dict)

    @auth.auth_required
    async def post(self):
        json_data = await self.request.json()
        advertisement = Advertisement(
            header=json_data["header"], description=json_data["description"],
            user_id=int(await self.get_current_user())
        )
        await add_advertisement(advertisement, self.session)
        return web.json_response(advertisement.id_dict)

    @auth.auth_required
    async def patch(self):
        json_data = await self.request.json()
        advertisement = await get_advertisement_by_id(self.adv_id, self.session)
        if int(await self.get_current_user()) == advertisement.user_id:
            if "header" in json_data:
                advertisement.header = json_data["header"]
            if "description" in json_data:
                advertisement.description = json_data["description"]

            await add_advertisement(advertisement, self.session)
            return web.json_response(advertisement.id_dict)
        return web.json_response({"status": "no permission"})

    @auth.auth_required
    async def delete(self):
        advertisement = await get_advertisement_by_id(self.adv_id, self.session)
        if int(await self.get_current_user()) == advertisement.user_id:
            await delete_advertisement(advertisement, self.session)
            return web.json_response({"status": "success"})
        return web.json_response({"status": "no permission"})

app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)

app.add_routes(
    [
        web.post("/api/v1/login", login),
        web.get("/api/v1/advertisement/{user_id:[0-9]+}", AdvertisementView),
        web.patch("/api/v1/advertisement/{user_id:[0-9]+}", AdvertisementView),
        web.delete("/api/v1/advertisement/{user_id:[0-9]+}", AdvertisementView),
        web.post("/api/v1/advertisement", AdvertisementView),
    ]
)

web.run_app(app)