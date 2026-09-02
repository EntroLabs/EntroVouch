"""Imports the local `motor` module. Must not be reported as network-import."""
import motor


def rotate(degrees: int) -> int:
    return motor.steps_for(degrees)
