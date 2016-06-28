Description
===========

A generic honeypot following an idea similar to honeytrap (but with a much
safer language and hopefully less bugs).

It manages TCP, UDP connections as well as PINGs. From an attacker point of
view it shows all ports open and logs all attack attemps no matter the port.

Of course due to its genericity it doesn't handle specific protocols well but
hopefully won't conflict with other honeypots so you can just use more
specialized tools where needed (cowrie for example is a very good SSH
honeypot).

This work is **heavily in progress**

Usage
=====

::

    -i --interface Device to listen to.
    -p      --port Port to listen to.
    -h      --help This help information.

Dependencies
============

- libpcap-d-bindings: https://github.com/cym13/libpcap-d-bindings
- cerealed: https://github.com/atilaneves/cerealed

Install
=======

Use dub to manage dependencies and compile:

::

    $ dub build -b plain
    $ sudo ./donutrap

License
=======

This program is under the GPLv3 License.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

Contact
=======

::

    Main developper: Cédric Picard
    Email:           cedric.picard@efrei.net

