from app import create_app
import os
from config import DevelopmentConfig, ProductionConfig

if os.getenv("MODE", "development") == "development":
    app = create_app(DevelopmentConfig)
else:
    app = create_app(ProductionConfig)

if __name__ == '__main__':
    app.run(debug=app.config["DEBUG"])