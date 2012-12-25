Description: Move hpfeeds.py tp right place
 dionaea-nisl (0.1.0.3-0.6) precise; urgency=low
 .
   * Merge and add untracked files
Author: Xiaoyu Liu (Vury Leo) <i@vuryleo.com>

---
The information above should follow the Patch Tagging Guidelines, please
checkout http://dep.debian.net/deps/dep3/ to learn about the format. Here
are templates for supplementary fields that you might want to add:

Origin: <vendor|upstream|other>, <url of original patch>
Bug: <url in upstream bugtracker>
Bug-Debian: http://bugs.debian.org/<bugnumber>
Bug-Ubuntu: https://launchpad.net/bugs/<bugnumber>
Forwarded: <no|not-needed|url proving that it has been forwarded>
Reviewed-By: <name and email of someone who approved the patch>
Last-Update: <YYYY-MM-DD>

--- a/Makefile.in
+++ b/Makefile.in
@@ -325,7 +325,7 @@
 stamp-h1: $(srcdir)/config.h.in $(top_builddir)/config.status
 	@rm -f stamp-h1
 	cd $(top_builddir) && $(SHELL) ./config.status config.h
-$(srcdir)/config.h.in:  $(am__configure_deps)
+$(srcdir)/config.h.in:  $(am__configure_deps) 
 	($(am__cd) $(top_srcdir) && $(AUTOHEADER))
 	rm -f stamp-h1
 	touch $@
--- a/modules/python/scripts/Makefile.am
+++ b/modules/python/scripts/Makefile.am
@@ -38,6 +38,7 @@
 PYSCRIPTS += cmd.py
 PYSCRIPTS += emu.py
 PYSCRIPTS += ihandlers.py
+PYSCRIPTS += hpfeeds.py
 PYSCRIPTS += util.py
 PYSCRIPTS += store.py
 PYSCRIPTS += surfids.py
@@ -60,7 +61,7 @@
 
 
 all: $(PYSCRIPTS)
-	
+
 
 install-data-am: all
 	for i in $(PYSCRIPTS); do \
--- /dev/null
+++ b/modules/python/scripts/hpfeeds.py
@@ -0,0 +1,446 @@
+#********************************************************************************
+#*                               Dionaea
+#*                           - catches bugs -
+#*
+#*
+#*
+#* Copyright (C) 2010  Mark Schloesser
+#* 
+#* This program is free software; you can redistribute it and/or
+#* modify it under the terms of the GNU General Public License
+#* as published by the Free Software Foundation; either version 2
+#* of the License, or (at your option) any later version.
+#* 
+#* This program is distributed in the hope that it will be useful,
+#* but WITHOUT ANY WARRANTY; without even the implied warranty of
+#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+#* GNU General Public License for more details.
+#* 
+#* You should have received a copy of the GNU General Public License
+#* along with this program; if not, write to the Free Software
+#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
+#* 
+#* 
+#*             contact nepenthesdev@gmail.com  
+#*
+#*******************************************************************************/
+
+from dionaea.core import ihandler, incident, g_dionaea, connection
+from dionaea.util import sha512file
+
+import os
+import logging
+import struct
+import hashlib
+import json
+try: import pyev
+except: pyev = None
+
+logger = logging.getLogger('hpfeeds')
+logger.setLevel(logging.DEBUG)
+
+#def DEBUGPERF(msg):
+#	print(msg)
+#logger.debug = DEBUGPERF
+#logger.critical = DEBUGPERF
+
+BUFSIZ = 16384
+PUBMAXSIZE = 5*(1024*2)
+
+OP_ERROR        = 0
+OP_INFO         = 1
+OP_AUTH         = 2
+OP_PUBLISH      = 3
+OP_SUBSCRIBE    = 4
+
+MAXBUF = 1024**2+PUBMAXSIZE
+SIZES = {
+	OP_ERROR: 5+MAXBUF,
+	OP_INFO: 5+256+20,
+	OP_AUTH: 5+256+20,
+	OP_PUBLISH: 5+MAXBUF,
+	OP_SUBSCRIBE: 5+256*2,
+}
+
+CONNCHAN = 'dionaea.connections'
+CAPTURECHAN = 'dionaea.capture'
+DCECHAN = 'dionaea.dcerpcrequests'
+SCPROFCHAN = 'dionaea.shellcodeprofiles'
+UNIQUECHAN = 'mwbinary.dionaea.sensorunique'
+
+OFFERCHAN = 'dionaea.offer'
+EMU_SERVICESCHAN = 'dionaea.emu_services'
+MSSQL_COMMANDSCHAN = 'dionaea.mssql_command'
+MSSQL_FINGERPRINTSCHAN = 'dionaea.mssql_fingerprint'
+MSSQL_LOGINSCHAN = 'dionaea.mssql_logins'
+DECRPCBINDCHAN = 'dionaea.dcerpcbind'
+P0FCHAN = 'dionaea.p0f'
+
+class BadClient(Exception):
+        pass
+
+# packs a string with 1 byte length field
+def strpack8(x):
+	if isinstance(x, str): x = x.encode('latin1')
+	return struct.pack('!B', len(x)%0xff) + x
+
+# unpacks a string with 1 byte length field
+def strunpack8(x):
+	l = x[0]
+	return x[1:1+l], x[1+l:]
+	
+def msghdr(op, data):
+	return struct.pack('!iB', 5+len(data), op) + data
+def msgpublish(ident, chan, data):
+	return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data)
+def msgsubscribe(ident, chan):
+	if isinstance(chan, str): chan = chan.encode('latin1')
+	return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)
+def msgauth(rand, ident, secret):
+	hash = hashlib.sha1(bytes(rand)+secret).digest()
+	return msghdr(OP_AUTH, strpack8(ident) + hash)
+
+class FeedUnpack(object):
+	def __init__(self):
+		self.buf = bytearray()
+	def __iter__(self):
+		return self
+	def __next__(self):
+		return self.unpack()
+	def feed(self, data):
+		self.buf.extend(data)
+	def unpack(self):
+		if len(self.buf) < 5:
+			raise StopIteration('No message.')
+
+		ml, opcode = struct.unpack('!iB', self.buf[:5])
+		if ml > SIZES.get(opcode, MAXBUF):
+			raise BadClient('Not respecting MAXBUF.')
+
+		if len(self.buf) < ml:
+			raise StopIteration('No message.')
+
+		data = self.buf[5:ml]
+		del self.buf[:ml]
+		return opcode, data
+
+class hpclient(connection):
+	def __init__(self, server, port, ident, secret):
+		logger.debug('hpclient init')
+		connection.__init__(self, 'tcp')
+		self.unpacker = FeedUnpack()
+		self.ident, self.secret = ident.encode('latin1'), secret.encode('latin1')
+
+		self.connect(server, port)
+		self.timeouts.reconnect = 10.0
+		self.sendfiles = []
+		self.msgqueue = []
+		self.filehandle = None
+		self.connected = False
+
+	def handle_established(self):
+		self.connected = True
+		logger.debug('hpclient established')
+
+	def handle_io_in(self, indata):
+		self.unpacker.feed(indata)
+
+		# if we are currently streaming a file, delay handling incoming messages
+		if self.filehandle:
+			return len(indata)
+
+		try:
+			for opcode, data in self.unpacker:
+				logger.debug('hpclient msg opcode {0} data {1}'.format(opcode, data))
+				if opcode == OP_INFO:
+					name, rand = strunpack8(data)
+					logger.debug('hpclient server name {0} rand {1}'.format(name, rand))
+					self.send(msgauth(rand, self.ident, self.secret))
+
+				elif opcode == OP_PUBLISH:
+					ident, data = strunpack8(data)
+					chan, data = strunpack8(data)
+					logger.debug('publish to {0} by {1}: {2}'.format(chan, ident, data))
+
+				elif opcode == OP_ERROR:
+					logger.debug('errormessage from server: {0}'.format(data))
+				else:
+					logger.debug('unknown opcode message: {0}'.format(opcode))
+		except BadClient:
+			logger.critical('unpacker error, disconnecting.')
+			self.close()
+
+		return len(indata)
+
+	def handle_io_out(self):
+		if self.filehandle: self.sendfiledata()
+		else:
+			if self.msgqueue:
+				m = self.msgqueue.pop(0)
+				self.send(m)
+
+	def publish(self, channel, **kwargs):
+		if self.filehandle: self.msgqueue.append(msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1')))
+		else: self.send(msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1')))
+
+	def sendfile(self, filepath):
+		# does not read complete binary into memory, read and send chunks
+		if not self.filehandle:
+			self.sendfileheader(filepath)
+			self.sendfiledata()
+			self.filehandle = None
+		else: self.sendfiles.append(filepath)
+
+	def sendfileheader(self, filepath):
+		self.filehandle = open(filepath, 'rb')
+		fsize = os.stat(filepath).st_size
+		if fsize > PUBMAXSIZE:
+			fsize = PUBMAXSIZE
+		headc = strpack8(self.ident) + strpack8(UNIQUECHAN)
+		headh = struct.pack('!iB', 5+len(headc)+fsize, OP_PUBLISH)
+		self.send(headh + headc)
+
+	def sendfiledata(self):
+		tmp = self.filehandle.read(PUBMAXSIZE)
+		if not tmp:
+			if self.sendfiles:
+				fp = self.sendfiles.pop(0)
+				self.sendfileheader(fp)
+			else:
+				self.filehandle = None
+				self.handle_io_in(b'')
+		else:
+			self.send(tmp)
+
+	def handle_timeout_idle(self):
+		pass
+
+	def handle_disconnect(self):
+		logger.info('hpclient disconnect')
+		self.connected = False
+		return 1
+
+	def handle_error(self, err):
+		logger.warn('hpclient error {0}'.format(err))
+		self.connected = False
+		return 1
+
+class hpfeedihandler(ihandler):
+	def __init__(self, config):
+		logger.debug('hpfeedhandler init')
+		self.client = hpclient(config['server'], int(config['port']), config['ident'], config['secret'])
+		ihandler.__init__(self, '*')
+
+		self.dynip_resolve = config.get('dynip_resolve', '')
+		self.dynip_timer = None
+		self.ownip = None
+		if self.dynip_resolve and 'http' in self.dynip_resolve:
+			if pyev == None:
+				logger.debug('You are missing the python pyev binding in your dionaea installation.')
+			else:
+				logger.debug('hpfeedihandler will use dynamic IP resolving!')
+				self.loop = pyev.default_loop()
+				self.dynip_timer = pyev.Timer(2., 300, self.loop, self._dynip_resolve)
+				self.dynip_timer.start()
+
+	def stop(self):
+		if self.dynip_timer:
+			self.dynip_timer.stop()
+			self.dynip_timer = None
+			self.loop = None
+
+	def _ownip(self, icd):
+		if self.dynip_resolve and 'http' in self.dynip_resolve and pyev != None:
+			if self.ownip: return self.ownip
+			else: raise Exception('Own IP not yet resolved!')
+		return icd.con.local.host
+
+	def __del__(self):
+		#self.client.close()
+		pass
+
+	def connection_publish(self, icd, con_type):
+		try:
+			con=icd.con
+			self.client.publish(CONNCHAN, connection_type=con_type, connection_transport=con.transport, connection_protocol=con.protocol, remote_host=con.remote.host, remote_port=con.remote.port, remote_hostname=con.remote.hostname, local_host=con.local.host, local_port=con.local.port)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident(self, i):
+		pass
+	
+	def handle_incident_dionaea_connection_tcp_listen(self, icd):
+		self.connection_publish(icd, 'listen')
+		con=icd.con
+		logger.info("listen connection on %s:%i" % 
+			(con.remote.host, con.remote.port))
+
+	def handle_incident_dionaea_connection_tls_listen(self, icd):
+		self.connection_publish(icd, 'listen')
+		con=icd.con
+		logger.info("listen connection on %s:%i" % 
+			(con.remote.host, con.remote.port))
+
+	def handle_incident_dionaea_connection_tcp_connect(self, icd):
+		self.connection_publish(icd, 'connect')
+		con=icd.con
+		logger.info("connect connection to %s/%s:%i from %s:%i" % 
+			(con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port))
+
+	def handle_incident_dionaea_connection_tls_connect(self, icd):
+		self.connection_publish(icd, 'connect')
+		con=icd.con
+		logger.info("connect connection to %s/%s:%i from %s:%i" % 
+			(con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port))
+
+	def handle_incident_dionaea_connection_udp_connect(self, icd):
+		self.connection_publish(icd, 'connect')
+		con=icd.con
+		logger.info("connect connection to %s/%s:%i from %s:%i" % 
+			(con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port))
+
+	def handle_incident_dionaea_connection_tcp_accept(self, icd):
+		self.connection_publish(icd, 'accept')
+		con=icd.con
+		logger.info("accepted connection from  %s:%i to %s:%i" %
+			(con.remote.host, con.remote.port, con.local.host, con.local.port))
+
+	def handle_incident_dionaea_connection_tls_accept(self, icd):
+		self.connection_publish(icd, 'accept')
+		con=icd.con
+		logger.info("accepted connection from %s:%i to %s:%i" % 
+			(con.remote.host, con.remote.port, con.local.host, con.local.port))
+
+
+	def handle_incident_dionaea_connection_tcp_reject(self, icd):
+		self.connection_publish(icd, 'reject')
+		con=icd.con
+		logger.info("reject connection from %s:%i to %s:%i" % 
+			(con.remote.host, con.remote.port, con.local.host, con.local.port))
+
+	def handle_incident_dionaea_connection_tcp_pending(self, icd):
+		self.connection_publish(icd, 'pending')
+		con=icd.con
+		logger.info("pending connection from %s:%i to %s:%i" % 
+			(con.remote.host, con.remote.port, con.local.host, con.local.port))
+	
+	def handle_incident_dionaea_download_complete_unique(self, i):
+		self.handle_incident_dionaea_download_complete_again(i)
+		if not hasattr(i, 'con') or not self.client.connected: return
+		logger.debug('unique complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
+		try:
+			self.client.sendfile(i.file)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_download_complete_again(self, i):
+		if not hasattr(i, 'con') or not self.client.connected: return
+		logger.debug('hash complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
+		try:
+			f = open(i.file,'rb')
+			fdata = f.read(PUBMAXSIZE)
+			sha1 = hashlib.sha1(fdata).hexdigest()
+			sha512 = hashlib.sha512(fdata).hexdigest()
+			fmd5 = hashlib.md5(fdata).hexdigest()
+			f.close()
+			self.client.publish(CAPTURECHAN, remote_host=i.con.remote.host, 
+				remote_port=str(i.con.remote.port), local_host=self._ownip(i),
+				local_port=str(i.con.local.port), md5=fmd5, sha512=sha512,
+				url=i.url,sha1=sha1,connection_transport=i.con.transport,
+			)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, i):
+		if not hasattr(i, 'con') or not self.client.connected: return
+		logger.debug('dcerpc request, publishing uuid {0}, opnum {1}'.format(i.uuid, i.opnum))
+		try:
+			self.client.publish(DCECHAN, uuid=i.uuid, opnum=i.opnum,
+				remote_host=i.con.remote.host, remote_port=str(i.con.remote.port),
+				local_host=self._ownip(i), local_port=str(i.con.local.port),connection_transport=i.con.transport,
+			)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_module_emu_profile(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('emu profile, publishing length {0}'.format(len(icd.profile)))
+		try:
+			self.client.publish(SCPROFCHAN, profile=icd.profile,remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=self._ownip(icd), local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def _dynip_resolve(self, events, data):
+		i = incident("dionaea.upload.request")
+		i._url = self.dynip_resolve
+		i._callback = "dionaea.modules.python.hpfeeds.dynipresult"
+		i.report()
+
+	def handle_incident_dionaea_modules_python_hpfeeds_dynipresult(self, icd):
+		fh = open(icd.path, mode="rb")
+		self.ownip = fh.read().strip()
+		logger.debug('resolved own IP to: {0}'.format(self.ownip))
+		fh.close()
+
+	def handle_incident_dionaea_download_offer(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('offer, publishing offer_url {0}'.format(str(icd.url)))
+		try:
+			self.client.publish(OFFERCHAN, offer_url=icd.url,remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_service_shell_listen(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('emu_services, publishing...')
+		try:
+			self.client.publish(EMU_SERVICECHAN, emu_service_url="bindshell://"+str(icd.port),remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+				
+	def handle_incident_dionaea_service_shell_connect(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('emu_services, publishing...')
+		try:
+			self.client.publish(EMU_SERVICESCHAN, emu_service_url="connectbackshell://"+str(icd.host)+":"+str(icd.port),remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_modules_python_p0f(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('p0f, publishing...')
+		try:
+			self.client.publish(P0FCHAN, p0f_genre=icd.genre, p0f_link=icd.link, p0f_detail=icd.detail, p0f_uptime=icd.uptime, p0f_tos=icd.tos, p0f_dist=icd.dist, p0f_nat=icd.nat, p0f_fw=icd.fw,remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('dcerpc_bind, publishing dcerpcbind_transfersyntax {0}'.format(icd.transfersyntax))
+		try:
+			self.client.publish(DECRPCBINDCHAN, dcerpcbind_uuid=icd.uuid, dcerpcbind_transfersyntax=icd.transfersyntax,remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_modules_python_mssql_login(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('mssql_login, publishing...')
+		try:
+			self.client.publish(MSSQL_LOGINSCHAN, login_username=icd.username, login_password=icd.password,remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,mssql_fingerprint_hostname=icd.hostname, mssql_fingerprint_appname=icd.appname, mssql_fingerprint_cltintname=icd.cltintname,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))
+
+	def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
+		if not hasattr(icd, 'con') or not self.client.connected: return
+		logger.debug('mssql_cmd, publishing...')
+		try:
+			self.client.publish(MSSQL_COMMANDSCHAN, mssql_command_statu=icd.status, mssql_command_cmd=icd.cmd,remote_host=icd.con.remote.host, remote_port=str(icd.con.remote.port),
+				local_host=icd.con.local.host, local_port=str(icd.con.local.port),connection_transport=icd.con.transport,)
+		except Exception as e:
+			logger.warn('exception when publishing: {0}'.format(e))	
--- a/modules/python/scripts/Makefile.in
+++ b/modules/python/scripts/Makefile.in
@@ -229,7 +229,7 @@
 	smb/include/ntlmfields.py smb/include/gssapifields.py \
 	smb/__init__.py smb/smb.py smb/rpcservices.py test.py \
 	mirror.py nfq.py http.py log.py logsql.py p0f.py cmd.py emu.py \
-	ihandlers.py util.py store.py surfids.py virustotal.py \
+	ihandlers.py hpfeeds.py util.py store.py surfids.py virustotal.py \
 	mwserv.py submit_http.py ndrlib.py logxmpp.py fail2ban.py \
 	__init__.py mssql/__init__.py mssql/mssql.py \
 	mssql/include/tds.py mssql/include/__init__.py \
--- a/autom4te.cache/requests
+++ b/autom4te.cache/requests
@@ -247,10 +247,10 @@
                         'configure.ac'
                       ],
                       {
-                        '_LT_AC_TAGCONFIG' => 1,
                         'AM_PROG_F77_C_O' => 1,
-                        'AC_INIT' => 1,
+                        '_LT_AC_TAGCONFIG' => 1,
                         'm4_pattern_forbid' => 1,
+                        'AC_INIT' => 1,
                         'AC_CANONICAL_TARGET' => 1,
                         '_AM_COND_IF' => 1,
                         'AC_CONFIG_LIBOBJ_DIR' => 1,
@@ -263,8 +263,8 @@
                         'AM_PATH_GUILE' => 1,
                         'AM_AUTOMAKE_VERSION' => 1,
                         'LT_CONFIG_LTDL_DIR' => 1,
-                        'AC_REQUIRE_AUX_FILE' => 1,
                         'AC_CONFIG_LINKS' => 1,
+                        'AC_REQUIRE_AUX_FILE' => 1,
                         'LT_SUPPORTED_TAG' => 1,
                         'm4_sinclude' => 1,
                         'AM_MAINTAINER_MODE' => 1,
@@ -273,26 +273,26 @@
                         '_m4_warn' => 1,
                         'AM_MAKEFILE_INCLUDE' => 1,
                         'AM_PROG_CXX_C_O' => 1,
-                        '_AM_COND_ENDIF' => 1,
                         '_AM_MAKEFILE_INCLUDE' => 1,
+                        '_AM_COND_ENDIF' => 1,
                         'AM_ENABLE_MULTILIB' => 1,
-                        'AM_PROG_MOC' => 1,
                         'AM_SILENT_RULES' => 1,
+                        'AM_PROG_MOC' => 1,
                         'AC_CONFIG_FILES' => 1,
-                        'include' => 1,
                         'LT_INIT' => 1,
-                        'AM_PROG_AR' => 1,
+                        'include' => 1,
                         'AM_GNU_GETTEXT' => 1,
+                        'AM_PROG_AR' => 1,
                         'AC_LIBSOURCE' => 1,
                         'AC_CANONICAL_BUILD' => 1,
                         'AM_PROG_FC_C_O' => 1,
                         'AC_FC_FREEFORM' => 1,
                         'AH_OUTPUT' => 1,
-                        '_AM_SUBST_NOTMAKE' => 1,
                         'AC_CONFIG_AUX_DIR' => 1,
+                        '_AM_SUBST_NOTMAKE' => 1,
+                        'm4_pattern_allow' => 1,
                         'AM_PROG_CC_C_O' => 1,
                         'sinclude' => 1,
-                        'm4_pattern_allow' => 1,
                         'AM_CONDITIONAL' => 1,
                         'AC_CANONICAL_SYSTEM' => 1,
                         'AM_XGETTEXT_OPTION' => 1,
