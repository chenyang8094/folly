'''
author yunhai
created on 2016.9.2
'''
from conans import ConanFile, CMake

class TeslacppsdkConan(ConanFile):
    name = "tesla-cpp-sdk"
    version = "1.2.1"
    settings = "os", "compiler", "build_type", "arch"
    requires = (("libevent/2.0.22@theirix/stable"),
                ("glog/0.3.4@eliaskousk/stable"),
                ("double-conversion/1.1.5@jhonatandarosa/stable"),
                ("gflags/2.2.0@eliaskousk/stable"),
                ("Boost/1.60.0@lasote/stable"),
                ("snappy/1.1.3@hoxnox/testing"),
                ("OpenSSL/1.0.2g@lasote/stable"),
                ("jemalloc/4.3.1@selenorks/testing"),
                ("zlib/1.2.8@lasote/stable")
                )
    generators = "cmake"
    exports = ["src/*","test/conanfile.py","CMakeLists.txt","conanfile.py"]

    def conan_info(self):
        if self.settings.os == "Linux":
            self.info.settings.compiler.version = "4.9"
        if self.settings.os == "Macos":
            self.info.settings.compiler.version = "any"

    def config(self):
        try: # Try catch can be removed when conan 0.8 is released
            del self.settings.compiler.libcxx
        except:
            pass

    def build(self):
        """ Define your project building. You decide the way of building it
            to reuse it later in any other project.
        """
        cmake = CMake(self.settings)
        self.run("rm -rf _build")
        self.run("mkdir _build")
        cd_build = "cd _build"
        self.run('%s && cmake .. %s  -DBUILD_SHARED_LIBS=OFF' % (cd_build, cmake.command_line))
        self.run("%s && cmake --build . %s" % (cd_build, cmake.build_config))

    def package(self):
        """ Define your conan structure: headers, libs, bins and data. After building your
            project, this method is called to create a defined structure:
        """
        self.copy("*.h*", dst="include/", src="./src/tesla", keep_path=True)
        self.copy("*.h*", dst="include/hessian/", src="./src/serializer/hessian/include/hessian/", keep_path=True)
        self.copy(pattern="*.a", dst="lib", src="_build", keep_path=False)
    def package_info(self):
        self.cpp_info.libs = ["tesla-cpp-sdk"]
