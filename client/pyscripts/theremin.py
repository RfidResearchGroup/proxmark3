#!/usr/bin/python3

import os
import subprocess
import signal
import numpy as np
from pyaudio import PyAudio, paFloat32, paContinue

# Sound output parameters
volume = 1.0
sampling_freq = 44100  # Hz

# Frequency generator parameters
min_freq = 100   # Hz
max_freq = 6000  # Hz

# Proxmark3 parameters
pm3_client = "pm3"
pm3_tune_cmd = "hf tune --value"

frequency = 440
buffer = []


def find_zero_crossing_index(array):
    for i in range(1, len(array)):
        if array[i-1] < 0 and array[i] >= 0:
            return i
    return None  # Return None if no zero-crossing is found


def generate_sine_wave(frequency, sample_rate, duration, frame_count):
    """Generate a sine wave at a given frequency."""
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    wave = np.sin(2 * np.pi * frequency * t)
    return wave[:frame_count]


# PyAudio Callback function
def pyaudio_callback(in_data, frame_count, time_info, status):
    # if in_data is None:
    #     return (in_data, pyaudio.paContinue)
    global frequency
    global buffer
    wave = generate_sine_wave(frequency, sampling_freq, 0.01, frame_count*2)
    i = find_zero_crossing_index(buffer)
    if i is None:
        buffer = wave
    else:
        buffer = np.concatenate((buffer[:i], wave))
    data = (buffer[:frame_count] * volume).astype(np.float32).tobytes()
    buffer = buffer[frame_count:]
    return (data, paContinue)
# pyaudio.paComplete


def silent_pyaudio():
    """
    Lifted and adapted from https://stackoverflow.com/questions/67765911/
    PyAudio is noisy af every time you initialise it, which makes reading the
    log output rather difficult.  The output appears to be being made by the
    C internals, so we can't even redirect the logs with Python's logging
    facility.  Therefore the nuclear option was selected: swallow all stderr
    and stdout for the duration of PyAudio's use.
    """

    # Open a pair of null files
    null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
    # Save the actual stdout (1) and stderr (2) file descriptors.
    save_fds = [os.dup(1), os.dup(2)]
    # Assign the null pointers to stdout and stderr.
    os.dup2(null_fds[0], 1)
    os.dup2(null_fds[1], 2)
    pyaudio = PyAudio()
    os.dup2(save_fds[0], 1)
    os.dup2(save_fds[1], 2)
    # Close all file descriptors
    for fd in null_fds + save_fds:
        os.close(fd)
    return pyaudio


def run_pm3_cmd(callback):
    # Start the process
    process = subprocess.Popen(
        [pm3_client, '-c', pm3_tune_cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # Line buffered
        shell=False
    )

    # Read the output line by line as it comes
    try:
        with process.stdout as pipe:
            for line in pipe:
                # Process each line
                l = line.strip()  # Strip to remove any extraneous newline characters
                callback(l)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the subprocess is properly terminated
        process.terminate()
        process.wait()


def linear_to_exponential_freq(v, min_v, max_v, min_freq, max_freq):
    # First, map v to a range between 0 and 1
    if max_v != min_v:
        normalized_v = (v - min_v) / (max_v - min_v)
    else:
        normalized_v = 0.5
    normalized_v = 1 - normalized_v

    # Calculate the ratio of the max frequency to the min frequency
    freq_ratio = max_freq / min_freq

    # Calculate the exponential frequency using the mapped v
    freq = min_freq * (freq_ratio ** normalized_v)
    return freq


class foo():
    def __init__(self):
        self.p = silent_pyaudio()
        # For paFloat32 sample values must be in range [-1.0, 1.0]
        self.stream = self.p.open(format=paFloat32,
                             channels=1,
                             rate=sampling_freq,
                             output=True,
                             stream_callback=pyaudio_callback)

        # Initial voltage to frequency values
        self.min_v = 50000.0
        self.max_v = 0.0

        # Setting the signal handler for SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, self.signal_handler)

        # Start the stream
        self.stream.start_stream()

    def __exit__(self):
        self.stream.stop_stream()
        self.stream.close()
        self.p.terminate()

    def signal_handler(self, sig, frame):
        print("\nYou pressed Ctrl+C! Press Enter")
        self.__exit__()

    def callback(self, line):
        if 'mV' not in line:
            return
        v = int(line.split(' ')[1])
        if v == 0:
            return
        self.min_v = min(self.min_v, v)
        self.max_v = max(self.max_v, v)

        # Recalculate the audio frequency to generate
        global frequency
        frequency = linear_to_exponential_freq(v, self.min_v, self.max_v, min_freq, max_freq)

#        frequency = max_freq - ((max_freq - min_freq) * (v - self.min_v) / (self.max_v - self.min_v) + min_freq)
        #frequency = (frequency + new_frequency)/2


def main():
    f = foo()
    run_pm3_cmd(f.callback)


if __name__ == "__main__":
    main()
