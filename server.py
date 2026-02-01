from os import urandom
from aiohttp.web_exceptions import HTTPNotFound, HTTPBadRequest, HTTPUnauthorized, HTTPForbidden
from aiohttp.web_middlewares import middleware
from sqlalchemy.exc import IntegrityError
from models import Advertisement, Session, User, init_orm, close_orm
from auth import check_password
from sqlalchemy import select
import json
from aiohttp import web
from aiohttp_auth import auth

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
    json_data = await request.json()

    email = json_data.get("email")
    password = json_data.get("password")

    if not email:
        raise generate_error(HTTPBadRequest, "Email is not provided")
    if not password:
        raise generate_error(HTTPBadRequest, "Password is not provided")

    query = await request.session.execute(select(User).filter_by(email=email))
    user = query.scalars().first()

    if user and check_password(password, user.password):
        await auth.remember(request, str(user.id))
        return web.json_response(
            {"status": "Logged in successfully"},
            content_type='application/json',
            status=200
        )

    raise generate_error(HTTPUnauthorized, "Invalid credentials")


@auth.auth_required
async def logout(request):
    await auth.forget(request)
    return web.json_response(
        {"status": "logged out"},
        content_type='application/json',
        status=200
    )


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
    await session.delete(advertisement)
    await session.commit()


async def get_current_user_id(request):
    user_id = int(await auth.get_auth(request))
    return user_id


class AdvertisementView(web.View):
    @property
    def session(self):
        return self.request.session

    @property
    def adv_id(self):
        return int(self.request.match_info["adv_id"])

    async def get_current_advertisement(self):
        advertisement = await get_advertisement_by_id(self.adv_id, self.session)
        return advertisement

    async def get(self):
        advertisement = await self.get_current_advertisement()

        return web.json_response(
            advertisement.dict,
            content_type='application/json',
            status=200
        )

    @auth.auth_required
    async def post(self):
        json_data = await self.request.json()
        header = json_data.get("header")
        if not header:
            raise generate_error(HTTPBadRequest, "header is required")

        user_id = await get_current_user_id(self.request)
        advertisement = Advertisement(
            header=header, description=json_data.get("description"),
            user_id=user_id
        )
        await add_advertisement(advertisement, self.session)

        return web.json_response(
            advertisement.id_dict,
            content_type='application/json',
            status=201
        )

    @auth.auth_required
    async def patch(self):
        advertisement = await get_advertisement_by_id(self.adv_id, self.session)
        json_data = await self.request.json()

        if await get_current_user_id(self.request) == advertisement.user_id:
            if "header" in json_data:
                advertisement.header = json_data["header"]

            if "description" in json_data:
                advertisement.description = json_data["description"]

            await add_advertisement(advertisement, self.session)
        else:
            raise generate_error(HTTPForbidden, "no permission")

        return web.json_response(
            advertisement.id_dict,
            content_type='application/json',
            status=201
        )

    @auth.auth_required
    async def delete(self):
        advertisement = await get_advertisement_by_id(self.adv_id, self.session)
        if await get_current_user_id(self.request) == advertisement.user_id:
            await delete_advertisement(advertisement, self.session)
        else:
            raise generate_error(HTTPForbidden, "no permission")

        return web.json_response(
            {"status": "success"},
            content_type='application/json',
            status=204
        )


if __name__ == "__main__":
    policy = auth.CookieTktAuthentication(urandom(32), 3600, include_ip=True)
    app = web.Application(middlewares=[auth.auth_middleware(policy), session_middleware])
    app.cleanup_ctx.append(orm_context)

    app.add_routes(
        [
            web.post("/api/v1/login/", login),
            web.post("/api/v1/logout/", logout),
            web.get("/api/v1/advertisement/{adv_id:[0-9]+}", AdvertisementView),
            web.patch("/api/v1/advertisement/{adv_id:[0-9]+}", AdvertisementView),
            web.delete("/api/v1/advertisement/{adv_id:[0-9]+}", AdvertisementView),
            web.post("/api/v1/advertisement/", AdvertisementView),
        ]
    )

    web.run_app(app)