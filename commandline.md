# 命令行


  
  ```shell
  # 启动docker
  docker run -it --rm --name pintos --mount type=bind,source=absolute/path/to/pintos/on/your/host/machine,target=/home/PKUOS/pintos pkuflyingpig/pintos bash

  # 替换路径后
  docker run -it --rm --name pintos --mount type=bind,source=C:\Users\29694\Desktop\PKU\OS\pintos,target=/home/PKUOS/pintos pkuflyingpig/pintos bash

  # 启动另一个命令行
  docker exec -it pintos bash

  # build
  cd pintos/src/threads/
  make

  # start Pintos with the --gdb option
  cd pintos/src/threads/build
  pintos --gdb -- run mytest

  # 启动gdb 在第二个命令行窗口
  cd pintos/src/threads/build
  pintos-gdb kernel.o

  # gdb命令
  debugpintos

  # 编译并运行单个测试（根据需要更换测试名，注意要有.result后缀）
  make && make tests/threads/priority-donate-multiple.result

  # 编译并调试单个测试（根据需要更换测试名）
  make && pintos --gdb -- run priority-donate-multiple

  # run all tests
  make check

  # make grade 错误
  cd pintos/src/tests
  find . -type f -exec dos2unix {} +
  ```


