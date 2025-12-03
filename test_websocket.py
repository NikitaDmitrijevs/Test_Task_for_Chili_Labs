import socketio
import time
import sys

sio = socketio.Client()


@sio.event
def connect():
    print("Connected to WebSocket server")


@sio.event
def connected(data):
    print(f"Server greeting: {data}")


@sio.event
def avatar_changed(data):
    print(f"Avatar changed notification: {data}")


@sio.event
def user_deleted(data):
    print(f"User deleted notification: {data}")


@sio.event
def pong(data):
    print(f"Pong received: {data}")


@sio.event
def error(data):
    print(f"Error: {data}")


@sio.event
def disconnect():
    print("Disconnected from server")


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_websocket.py <JWT_TOKEN>")
        sys.exit(1)

    token = sys.argv[1]

    try:
        sio.connect(f'http://localhost:5000?token={token}')
        print(f"WebSocket connected with token: {token[:50]}...")

        sio.emit('ping', {'test': 'data'})

        print("Waiting for notifications...")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping...")
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        sio.disconnect()


if __name__ == '__main__':
    main()