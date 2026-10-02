"""Receive telemetry from provisioned edge devices."""

from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

ALLOWED_MAC_ADDRESSES = frozenset({"60:e8:5b:08:2a:00"})

app = FastAPI(title="Edge Command Backend")


class Telemetry(BaseModel):
    """Telemetry submitted by an edge device."""

    mac_address: str
    cpu_temp: float
    timestamp: datetime


@app.post("/api/v1/telemetry", status_code=status.HTTP_200_OK)
def receive_telemetry(payload: Telemetry) -> dict[str, str]:
    """Accept telemetry from an allowed device."""

    if payload.mac_address.strip().lower() not in ALLOWED_MAC_ADDRESSES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device is not authorized",
        )
    return {"status": "Active"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
