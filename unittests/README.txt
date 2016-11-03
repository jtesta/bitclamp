Because of its complexity, Bitclamp has a unit testing framework that greatly eases development.

The framework is designed to be installed in a dedicated, isolated Ubuntu 16.04 virtual machine because some functions are run as the root user.  Extensive testing for side-effects of these operations has not been done.

Additionally, the following prerequisites must be met:

  * The VM must have at least 4GB of RAM.
  * Bitcoin Classic or Bitcoin Core must be installed (Classic is preferred).
  * Dogecoin must be installed.

Once you're ready to proceed, you can install the environment by running 'make initdev' from the top-level directory.  The unit tests can be run with 'make coretests' or 'make alltests'.

To fully remove the unit test environment, run 'make wipedev'.
