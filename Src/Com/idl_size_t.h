/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifdef _WIN64
  typedef hyper int my_ssize_t;
  typedef unsigned hyper int my_size_t;
#else //_WIN64
  typedef long my_ssize_t;
  typedef unsigned long my_size_t;
#endif //_WIN64