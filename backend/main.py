from fastapi import FastAPI

from app.api.v1.endpoints import auth
from app.db.session import Base, engine


Base.metadata.create_all(bind=engine)



app = FastAPI(title="HR AI System Backend")

@app.get("/")
def read_root():
    return {"status": "ok", "message": "API is running! Visit /docs for the Swagger UI."}

app.include_router(auth.router)
