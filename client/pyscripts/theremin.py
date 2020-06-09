#!/usr/bin/python3

### Parameters
# Sound output parameters
volume = 1.0
sample_buf_size = 44
sampling_freq = 44100 #Hz

# Frequency generator parameters
min_freq = 200  #Hz
max_freq = 2000 #Hz

# Proxmark3 parameters
pm3_client="/usr/local/bin/proxmark3"
pm3_reader_dev_file="/dev/ttyACM0"
pm3_tune_cmd="hf tune"


### Modules
import numpy
import pyaudio
from select import select
from subprocess import Popen, DEVNULL, PIPE


### Main program
p = pyaudio.PyAudio()

# For paFloat32 sample values must be in range [-1.0, 1.0]
stream = p.open(format=pyaudio.paFloat32,
		channels=1,
		rate=sampling_freq,
		output=True)

# Initial voltage to frequency values
min_v = 100.0
max_v = 0.0
v = 0
out_freq = min_freq

# Spawn the Proxmark3 client 
pm3_proc = Popen([pm3_client, pm3_reader_dev_file, "-c", pm3_tune_cmd],
		bufsize=0, env={}, stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL)
mv_recbuf = ""

# Read voltages from the Proxmark3, generate the sine wave, output to soundcard
sample_buf = [0.0 for x in range(0, sample_buf_size)]
i = 0
sinev = 0
while True:

  # Read Proxmark3 client's stdout and extract voltage values
  if(select([pm3_proc.stdout], [], [], 0)[0]):

    b = pm3_proc.stdout.read(256).decode("ascii")
    for c in b:
      if c in "0123456789 mV":
        mv_recbuf += c
      else:
        mv_recbuf = ""
      if mv_recbuf[-3:] == " mV":
        v = int(mv_recbuf[:-3]) / 1000
        if v < min_v:
          min_v = v - 0.001
        if v > max_v:
          max_v = v

        # Recalculate the audio frequency to generate
        out_freq = (max_freq - min_freq) * (max_v - v) / (max_v - min_v) + min_freq

  # Generate the samples and write them to the soundcard
  sinevs = out_freq / sampling_freq * numpy.pi * 2
  sample_buf[i] = sinev
  sinev += sinevs
  sinev = sinev if sinev < numpy.pi * 2 else sinev - numpy.pi * 2
  i = (i + 1) % sample_buf_size
  if not i:
    stream.write((numpy.sin(sample_buf) * volume).astype(numpy.float32).tobytes())
