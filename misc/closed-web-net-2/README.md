# Closed Web Net 2 [_snakeCTF 2025 Quals_]

**Category**: network\
**Author**: jotone

## Description

My contractor installed me a new domotic system with cameras support.
I bet that is super secure.
Also, I believe that the contractor scammed me because not all the advertised features are available.
_n.b.: we use TLS on both ports for infra requirements_

## Solution

The challenge presents two network services running on ports 8000 and 20000. An initial analysis is performed to determine the nature of these services and how they interact.

### Initial Reconnaissance

A preliminary scan of the provided ports reveals an HTTP server on port 8000 and a non-HTTP service on port 20000. The HTTP server consistently returns a `404 Not Found` status for all requests, suggesting that its content may be dynamically accessible after interacting with the other service.

Upon connecting to port 20000, the server responds with `*#*1##`. This distinctive message format is characteristic of the OpenWebNet (OWN) protocol, a system for home automation. The challenge title, "Closed Web Net 2", is also a hint to this.

### Protocol Analysis

With the protocol identified as OpenWebNet, relevant [documentation](https://developer.legrand.com/Documentation/) was consulted to understand its command structure. The documentation specifies different functionalities based on a `WHO` identifier. The challenge description suggest a camera system, which, according to the [documentation](https://developer.legrand.com/uploads/2019/12/WHO_7.pdf), corresponds to `WHO=7` (Multimedia System).

The documentation for `WHO=7` outlines the commands for interacting with video systems, including camera selection, image adjustments, and video streaming. It is noted that images are served over HTTP after a camera is selected via an OWN command.

### Camera System Interaction

The solver script is designed to interact with both the OWN and HTTP services. The OpenWebNet protocol requires a password for command execution, which is assumed to be the default, `12345`, as none was provided.

The interaction sequence is as follows:
1.  A connection is established with the OWN server on port 20000.
2.  Commands are sent to select a camera. The camera IDs are iterated from 4000 to 4010.
3.  Once a camera is selected, commands are sent to increase the image brightness and quality to ensure any embedded information is legible. The commands `*7*150##` (increase brightness) and `*7*180##` (increase quality) are used.
4.  An HTTP GET request is made to `http://<host>:8000/telecamera.php` to retrieve the camera image.

### Solver Implementation

A Python script, `main.py`, was developed to automate this process. The script utilises the following libraries:
-   `pyown`: To handle the OpenWebNet communication.
-   `httpx`: For asynchronous HTTP requests to the web server.
-   `Pillow`: For image manipulation.
-   `pyzbar`: For decoding QR codes from the retrieved images.

The script iterates through the camera IDs, adjusts image parameters, fetches the images, and attempts to find and decode a QR code within them.

The following images show the camera feed before the image adjustments.

![Initial camera feed](images/camera_4001.png)

![Camera feed with QR code](images/camera_4002.png)

### Recovering the Flag

After several adjustments to the image quality, a clear QR code is obtained from camera 4002.

![Final QR code](images/camera_4003.png)

The QR code is then decoded, revealing the flag: `snakeCTF{0pen_w3b_n3t_ag4in??}`
