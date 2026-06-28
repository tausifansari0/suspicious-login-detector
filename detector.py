"""
Suspicious Login Activity Detector
"""

from config import Config


def main():
    config = Config.load()

    print("Suspicious Login Activity Detector")
    print("Configuration Loaded")
    print(config.raw)


if __name__ == "__main__":
    main()