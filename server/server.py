from fastapi import FastAPI


def create_app():
    app = FastAPI(title="Server")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app

