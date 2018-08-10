pg_snakeoil - The PostgreSQL Antivirus

Running typical antivirus software on a PostgreSQL Server has severe
drawbacks such as severely affecting performance or making the system
no longer POSIX-compliant, which in turn is unsupported by the
community and threatens data consistency.  Further, the failure modes
are extremely problematic when a non-PostgreSQL-Aware scanner blocks
access to a file due to false-positives and bugs in the scanner
software.

We typically recommend not to run such software on PostgreSQL servers,
as PostgreSQL - in contrast to lesser software - knows how to discern
between code and data and will not execute any viruses stored in a
database.

Though, due to bureaucratical reasons, installing an antivirus cannot
be avoided by all of credativ's customers.  The motivation for
pg_snakeoil is to provide ClamAV scanning of all data entereing a
PostgreSQL in a way that does not interfere with the proper function
of PostgreSQL and does not cause collateral damage or unneccesary
downtimes.

This is facilitated by using pg_receivelogical to acquire the data
entering the server instead of file system access, allowing offloading
of the CPU-time required for scanning to another server. The reaction
to a positive ClamAV result is fully customizable from asynchronous
notification of the admins or synchronous denial of a commit to the
application.
