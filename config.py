import yaml
from dataclasses import dataclass


@dataclass
class Config:
    raw: dict

    @classmethod
    def load(cls, path="config.yaml"):
        with open(path, "r") as file:
            return cls(raw=yaml.safe_load(file))

    def __getitem__(self, key):
        return self.raw[key]