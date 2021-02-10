#ifndef LIBPM3HELPERPP_H
#define LIBPM3HELPERPP_H

class ConsoleHandler {
public:
  virtual int handle_output(char *string) = 0;
  virtual ~ConsoleHandler() {}
};

#endif // LIBPM3HELPERPP_H
