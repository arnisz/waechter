import asyncio
import redis.asyncio as redis
import os

async def main():
    r = redis.from_url("redis://localhost:6379/0", decode_responses=True)
    try:
        await r.ping()
        print("Connected to Redis!")
        await r.set("test_waechter", "hello", ex=10)
        val = await r.get("test_waechter")
        print("Retrieved:", val)
    except Exception as e:
        print("Redis error:", e)
        
asyncio.run(main())
