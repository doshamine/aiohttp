from asyncio import run

import aiohttp


async def main():
    async with aiohttp.ClientSession() as session:
        BASE_URL = "http://localhost:8080/api/v1"
        headers = {"content-type": "application/json"}

        response = await session.post(
            f"{BASE_URL}/login",
            headers=headers,
            json={
                "email": "<EMAIL1>",
                "password": "<PASSWORD1>"
            },
        )
        print(response.status)
        print(await response.json())

        response = await session.post(
            f"{BASE_URL}/advertisement/",
            json={
                "header": "Заметка",
                "description": "Важная"
            },
        )
        print(response.status)
        print(await response.json())

        response = await session.post(
            f"{BASE_URL}/advertisement/",
            json={
                "header": "Заметочка",
                "description": "Крайне важная"
            },
        )
        print(response.status)
        print(await response.json())

        response = await session.delete(
            f"{BASE_URL}/advertisement/1",
        )
        print(response.status)
        print(await response.json())

        response = await session.patch(
            f"{BASE_URL}/advertisement/2",
            json={"description": "Ну очень важная"},
        )
        print(response.status)
        print(await response.json())

        response = await session.get(
            f"{BASE_URL}/advertisement/2",
        )
        print(response.status)
        print(await response.json())

        response = await session.post(
            f"{BASE_URL}/login/",
            json={
                "email": "<EMAIL2>",
                "password": "<PASSWORD2>"
            },
        )
        print(response.status)
        print(await response.json())

        response = await session.get(
            f"{BASE_URL}/advertisement/2",
        )
        print(response.status)
        print(await response.json())

run(main())
