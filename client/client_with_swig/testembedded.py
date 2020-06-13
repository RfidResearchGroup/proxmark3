import sys
import pm3

def main():
    print('Hello world')
    #p=pm3.open("/dev/ttyACM0")
    p=pm3.get_current_dev()
    pm3.console(p, "hw status")
    #pm3.close(p)

if __name__ == "__main__":
    main()
