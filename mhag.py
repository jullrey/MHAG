#!/usr/bin/env python3
'''Multi Host Availability Grapher

  FILENAME: /home/mrtg/bin/mhag.py

  PURPOSE: Parse and format output from ping for use by rrdtool (MRTG).

  INSTALLED ON: Linux 4.14.79-v7+ #1159 SMP armv7l GNU/Linux

  DEPENDENCIES: /usr/bin/python3

  OUTPUT: Input, Output, Uptime, Hostname data for rrdtool (MRTG) to ingest.

  AUTHOR:
    John Ullrey, CISSP, CCNA Security, CCNP Routing & Switching
    Network Security Engineer SME
    Email: john at ullrey dot net

  LICENSE: GNU General Public License v3.0
    https://github.com/jullrey/MHAG/blob/master/LICENSE

  DATE: 22-Aug-2018

  -----------------------------------------------------------------------------
  REVISIONS:
  Date    Programmer  Description
  ------- ----------- ---------------------------------------------------------
  24Aug18 John Ullrey Added initial documentation
  31Aug18 John Ullrey Created main function and separate arg_parse function
  11Sep18 John Ullrey Setup multi host concurrent polling
  13Sep18 John Ullrey added RRD file creation changed name to mhag
  14Sep18 John Ullery moved temp polling data to separate polDict
  14Sep18 John Ullrey added database update capability
  15Sep18 John Ullrey added graphing capability
  17Sep18 John Ullrey fixed directory options
  26Sep18 John Ullrey lots of clean up based on pylint3 results
  28Sep18 John Ullrey consolodated graph building using gfx_dict dictionary
  08Oct18 John Ullrey Fixed problem overwriting elements in nested dictionaries
  08Oct18 John Ullrey working gen_html_index function
  12Oct18 John Ullrey removed global variable statemens pylint3 complained about
  30Nov18 John Ullrey print help if no args, made --data and --html required
  21Jan19 John Ullrey now capturing stderr in subprocess.check_output

'''
# -----------------------------------------------------------------------------
# --- Required Python Libraries. ----------------------------------------------
# -----------------------------------------------------------------------------
import sys
import argparse
import subprocess
import re
import time
import json
from collections import OrderedDict
from datetime import datetime, timedelta
from copy import deepcopy
from pytz import timezone

# -----------------------------------------------------------------------------
# --- Custom Function Imports.  -----------------------------------------------
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# --- Initialize global arrays and hashes. ------------------------------------
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# --- Global variables. -------------------------------------------------------
# -----------------------------------------------------------------------------
VER = '0.2'
STR_EPOCTIME = str(int(time.time()))
STR_DATETIME = str(datetime.now())
PING = '/bin/ping'
GREP = '/bin/grep'
RRDTOOL = '/usr/bin/rrdtool'
GRAPH_WIDTH = '398'
GRAPH_HEIGHT = '246'
LINE = '------------------------------------------------------------------------'
# -----------------------------------------------------------------------------
# --- Main function declaration -----------------------------------------------
# -----------------------------------------------------------------------------
def main():
	'''main function calls the rest'''

	cfg_dict = {}
	gfx_dict = {}
	pol_dict = {}

	# ARGS = parse_args() moved to if __name__ == '__main__': at end of script
	if ARGS.comments:
		print(__doc__)
		sys.exit()

	# Check and add trailing / to directory CLI variables
	if ('htmldir' in ARGS) and not re.search('/$', ARGS.htmldir):
		ARGS.htmldir += '/'
	if ('datadir' in ARGS) and not re.search('/$', ARGS.datadir):
		ARGS.datadir += '/'

	# Correct custom cfgfile input
	if not re.search(r'.json$', ARGS.cfgfile):
		ARGS.cfgfile += '.json'

	# Set default database file
	ARGS.dbfile = ARGS.cfgfile.replace('json', 'rrd')

	# Add ARGS.datadir path  toconfig and DBFILE
	if ARGS.datadir:
		ARGS.cfgfile = ARGS.datadir+ARGS.cfgfile
		ARGS.dbfile = ARGS.datadir+ARGS.dbfile

	dbug("BEGIN degugging info to STDERR")
	dbug("ARGS: "+str(ARGS))

	# Read/create [config.json] file
	read_config(ARGS.cfgfile, cfg_dict, gfx_dict)

	# Make a copy of cfg_dict to hold temporary polling data
	pol_dict = deepcopy(cfg_dict)

	# Verify/update Round Robin Database (RRD) file matches config file
	verify_rrd(cfg_dict)

	# Ping all hosts
	ping_hosts(cfg_dict, pol_dict)
	dbug(LINE)

	# Calculate uptime
	calc_uptime(cfg_dict)

	# Write updates to config file
	gfxprm_sort = OrderedDict(sorted(gfx_dict.items(), key=lambda \
		x: int(x[1]['step'])))

	with open(ARGS.cfgfile, mode='w', encoding='utf-8') as cfile:
		cfile.write(json.dumps([cfg_dict, gfxprm_sort], indent=4))

	# Write data to database
	update_database(pol_dict)

	# Generate Graphs
	gen_graphs(pol_dict, gfx_dict)
	gen_html_index(pol_dict, gfx_dict)

	dbug(LINE)
	dbug("END debugging output to STDERR")

# -----------------------------------------------------------------------------
# --- Remaining function declarations -----------------------------------------
# -----------------------------------------------------------------------------
def read_config(cfgfile, cfgdic, gfxdic):
	'''Read config file'''

	need2write = False

	dbug(LINE)
	try:
		dbug('Reading '+cfgfile+' configuration file.')
		with open(cfgfile, 'r', encoding='utf-8') as cfile:
			listofdic = json.load(cfile)

		cfgdic.update(listofdic[0])
		gfxdic.update(listofdic[1])

	except FileNotFoundError:
		dbug('Exception:', 'FileNotFoundError')
		# config file doesn't exist so create default one
		cfgdic.update({'Cloudflare': {'FQDN': 'one.one.one.one', 'COUNT': '5',\
			'LASTFAIL': STR_DATETIME},\
			'Google': {'FQDN': 'google-public-dns-a.google.com', 'COUNT': '5',\
			'LASTFAIL': STR_DATETIME},\
			'OpenDNS': {'FQDN': 'resolver1.opendns.com', 'COUNT': '5',\
			'LASTFAIL': STR_DATETIME},})
		need2write = True

	if not gfxdic:
		gfxdic.update({\
			'1mx12h': {'rra': 'LAST', 'interval': '1m', \
				'duration': '12h', 'step': '60', 'xgrid': \
				'MINUTE:5:MINUTE:15:HOUR:2'},\
			'5mx24h': {'rra': 'AVERAGE', 'interval': '5m', \
				'duration': '24h', 'step': '300', 'xgrid': \
				'MINUTE:5:MINUTE:15:HOUR:4'},\
			'30mx7d': {'rra': 'AVERAGE', 'interval': '30m', \
				'duration': '7d', 'step': '1800', 'xgrid': \
				'MINUTE:30:HOUR:4:HOUR:24'},\
			'2hx28d': {'rra': 'AVERAGE', 'interval': '2h', \
				'duration': '28d', 'step': '7200', 'xgrid': \
				'HOUR:2:DAY:1:DAY:7'},\
			'1dx365d': {'rra': 'AVERAGE', 'interval': '1d', \
				'duration': '365d', 'step': '86400', 'xgrid': \
				'HOUR:24:DAY:7:DAY:30'},})
		need2write = True

	if need2write:
		gfxprm_sort = OrderedDict(sorted(gfxdic.items(), key=lambda \
			x: int(x[1]['step'])))
		with open(cfgfile, mode='w', encoding='utf-8') as cfile:
			cfile.write(json.dumps([cfgdic, gfxprm_sort], indent=4))
		dbug("Created default config file.\n"+cfgfile+"\n"+ \
			json.dumps([cfgdic, gfxprm_sort], indent=4))

# -----------------------------------------------------------------------------
def verify_rrd(cfgdic):
	'''Verify and/or update the RRD file associated with config file'''

	dbug(LINE)
	dbug('Verify Round Robin Database file.')
	cmd = RRDTOOL+' info '+ARGS.dbfile+' |'+GREP+' index'
	info_cmd = [cmd]
	try:
		info = subprocess.check_output(info_cmd, shell=True, stderr=subprocess.STDOUT)
		dbug(cmd+"\n"+info.decode('utf-8'))

	except subprocess.CalledProcessError:
		dbug('Exception:', 'subprocess.CalledProcessError')


		# rrd file that corresponds to the config file does not exist
		dbug('Creating '+ARGS.dbfile+' file')
		# create rrd file that matches the config file
		cmd = RRDTOOL+' create '+ARGS.dbfile+' --step 1m '
		for target in sorted(cfgdic.keys()):
			cmd += 'DS:'+target+'-AVRTT:GAUGE:65:1:2000 '
			cmd += 'DS:'+target+'-AVAIL:GAUGE:65:0:100 '

		cmd += 'RRA:LAST:0:1:365d '
		cmd += 'RRA:AVERAGE:0.5:5m:24h '
		cmd += 'RRA:AVERAGE:0.5:30m:7d '
		cmd += 'RRA:AVERAGE:0.5:2h:28d '
		cmd += 'RRA:AVERAGE:0.5:1d:365d '
		dbug(cmd)
		create_cmd = [cmd]
		try:
			output = subprocess.check_output(create_cmd, shell=True)
		except subprocess.CalledProcessError:
			dbug('Exception:', 'subprocess.CalledProcessError')
			dbug("ERROR:", "\n"+output.decode('utf-8'))

# -----------------------------------------------------------------------------
def calc_uptime(cfgdic):
	'''Calculate & return uptime string since the last ping failure'''

	dbug('Calculate up times')

	for target in sorted(cfgdic.keys()):
		lastfail = datetime.strptime(cfgdic[target]['LASTFAIL'], "%Y-%m-%d %H:%M:%S.%f")
		uptime = datetime.now().strftime("%H:%M:%S")
		uptime += ' UP (since last ping fail) for '
		delta = abs(datetime.now() - lastfail)
		mins, secs = divmod(delta.total_seconds(), 60)
		hours, mins = divmod(mins, 60)
		days, hours = divmod(hours, 12)

		if days > 0:
			uptime += str(round(days))+" days, "
		if hours > 0:
			uptime += str(round(hours))+" hours, "
		if mins > 0:
			uptime += str(round(mins))+" minutes, "
		if secs > 0:
			uptime += str(round(secs))+" seconds"
		uptime += "."
		cfgdic[target]['UPTIME'] = uptime
		dbug(target+':', cfgdic[target]['UPTIME'])

# -----------------------------------------------------------------------------
def ping_hosts(cfgdic, poldic):
	'''ping through all hosts'''

	dbug(LINE)
	dbug('Spawn Ping commands...')
	# Build command and launch each subprocess
	for target in sorted(poldic.keys()):
		cmd = [PING, '-qc', poldic[target]['COUNT'], poldic[target]['FQDN']]
		dbug(target, cmd)
		poldic[target].update({'PID': subprocess.Popen(cmd, \
			stdout=subprocess.PIPE, stderr=subprocess.PIPE)})

	# Wait for each subprocess to end
	for target in sorted(poldic.keys()):
		poldic[target]['PID'].wait()

	dbug('Pings attmpts completed. Displaying results:')
	# Process each suprocess output
	for target in sorted(poldic.keys()):
		output, errors = poldic[target]['PID'].communicate()

		dbug(LINE)

		# parse the ping output
		parse_ping(poldic, target, output, errors)

		# update LASTPOLL in persistent cfg_dict
		cfgdic[target]['LASTPOLL'] = STR_DATETIME

		# Clear PID, not JSON serializable (for dbug output)
		poldic[target]['PID'] = ''

		# Clear UPTIME, correct uptime in cfg_dict (for dbug output)
		try: # if 1st run, UPTIME doesn't exist yet
			del poldic[target]['UPTIME']
		except KeyError:
			pass

		dbug(target, 'LASTFAIL:', cfgdic[target]['LASTFAIL'])
		dbug(target, 'LASTPOLL:', cfgdic[target]['LASTPOLL'])

	dbug("Ping data:\npoldic", json.dumps(poldic, indent=4, sort_keys=True))

# -----------------------------------------------------------------------------
def parse_ping(poldic, key, out, err):
	'''Parse output from ping command'''

	dbug('parse_ping key: '+key)
	dbug("parse_ping input:\n"+out.decode('utf-8'))
	dbug("parse_ping errors:\n"+err.decode('utf-8'))

	if err:
		dbug('parse_ping returend an error.')
		poldic[key].update({'IP': 'UNKNOWN', 'TX': 'UNKNOWN', 'RX': 'UNKNOWN',\
		'AVAIL': '0', 'LASTFAIL': STR_DATETIME, \
		'MINRTT': 'UNKNOWN', 'AVGRTT': 'UNKNOWN', 'MAXRTT': 'UNKNOWN', \
		'MDEV': 'UNKNOWN'})

	elif 'PING' in out.decode('utf-8'):
		token_specification = [r'PING\s+([\w\-.]+)\s+\(',\
			r'(\d+\.\d+\.\d+\.\d+)',\
			r'(\d+)\s+packets\s+transmitted,',\
			r'(\d+)\s+received,',\
			r'(\d+)\%\s+packet\s+loss,',\
			r'(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)',]

			# hostname [a-zA-Z0-9_.]
			# IP Address
			# packets transmitted
			# packets received
			# packet loss
			# rtt min/AVG/max/mdev or blank line

		tokens_re = re.compile(r'('+'|'.join(token_specification)+')',\
		re.VERBOSE | re.UNICODE | re.MULTILINE)

		match = []
		match = tokens_re.findall(out.decode('utf-8'))
		if match:
			#dbug('parse_ping matched:\n'+str(token_specification))
			# Store results from pings
			poldic[key].update({'IP': match[1][2], 'TX': match[2][3], \
				'RX':match[3][4]})
			poldic[key].update({'AVAIL': str(100 - int(match[4][5]))})
			if poldic[key]['AVAIL'] == '0':
				poldic[key].update({'MINRTT': 'UNKNOWN', \
					'AVGRTT': 'UNKNOWN', 'MAXRTT': 'UNKNOWN',\
					'MDEV': 'UNKNOWN', 'LASTFAIL': \
					STR_DATETIME})
			else:
				poldic[key].update({'MINRTT': str(round(float(\
					match[5][6]))), 'AVGRTT': str(round(float(\
					match[5][7]))), 'MAXRTT': str(round(float(\
					match[5][8]))), 'MDEV': str(round(float(\
					match[5][9])))})

		else:
			dbug('ERROR: "PING" not in output.')
			poldic[key].update({'IP': 'UNKNOWN', 'TX': 'UNKNOWN', \
				'RX': 'UNKNOWN', 'AVAIL': '0', 'LASTFAIL': \
				STR_DATETIME, 'MINRTT': 'UNKNOWN', \
				'AVGRTT': 'UNKNOWN', 'MAXRTT': 'UNKNOWN', 'MDEV': 'UNKNOWN'})

# -----------------------------------------------------------------------------
def update_database(poldic):
	'''Generate and run the database update command for poll results'''

	cmd = RRDTOOL+' update '+ARGS.cfgfile.replace('json', 'rrd')+' --template '

	for target in sorted(poldic.keys()):
		cmd += target+'-AVRTT:'+target+'-AVAIL:'
	cmd = re.sub(r":$", " ", cmd) # remove traling colon
	cmd += STR_EPOCTIME + ":"

	for target in sorted(poldic.keys()):
		cmd += poldic[target]['AVGRTT']+':'+poldic[target]['AVAIL']+':'
	cmd = re.sub(r":$", "", cmd) # remove training colon

	dbug(LINE)
	dbug("Update database:\n"+cmd)

	update_cmd = [cmd]
	try:
		output = subprocess.check_output(update_cmd, shell=True)
	except subprocess.CalledProcessError:
		dbug('Exception:', 'subprocess.CalledProcessError')
		dbug("ERROR:", "\n"+output.decode('utf-8'))

# -----------------------------------------------------------------------------
def build_graph_command(poldic, gfxdic, target, intdur):
	'''Build rrd graph commands for each interval'''

	str_date = datetime.now().strftime("%c")
	poldic[target]['graph-'+intdur] = \
		ARGS.htmldir+target+intdur+".png"
	rrdcmd = [RRDTOOL]
	rrdcmd.append("graph")
	rrdcmd.append(ARGS.htmldir+target+intdur+".png")
	rrdcmd.append('-w'+GRAPH_WIDTH+' -h'+GRAPH_HEIGHT)
	rrdcmd.append('-a'+'PNG')
	rrdcmd.append("--start")
	rrdcmd.append("-"+gfxdic[intdur]['duration'])
	rrdcmd.append("--end")
	rrdcmd.append("now")
	rrdcmd.append("--font")
	rrdcmd.append("DEFAULT:7:")
	rrdcmd.append("--title")
	rrdcmd.append("Multi Host Availability Grapher - "+target+ \
		" ("+intdur+")")
	rrdcmd.append("--watermark")
	rrdcmd.append(str_date+' - '+poldic[target]['FQDN']+ \
		' ['+poldic[target]['IP']+']')
	rrdcmd.append("--vertical-label")
	rrdcmd.append("Round Trip Time latency(ms)")
	rrdcmd.append("--right-axis-label")
	rrdcmd.append("Availability (%)")
	rrdcmd.append("--lower-limit")
	rrdcmd.append("0")
	rrdcmd.append("--right-axis")
	rrdcmd.append("1:0")
	rrdcmd.append("--x-grid")
	rrdcmd.append(gfxdic[intdur]['xgrid']+":0:%R")
	rrdcmd.append("--alt-y-grid")
	rrdcmd.append("--rigid")
	rrdcmd.append("DEF:"+target+"AVRTT="+ARGS.dbfile+":"+target+"-AVRTT:"\
		+gfxdic[intdur]['rra']+ ":step="+gfxdic[intdur]['step'])
	rrdcmd.append("DEF:"+target+"AVAIL="+ARGS.dbfile+":"+target+"-AVAIL:"\
		+gfxdic[intdur]['rra']+ ":step="+gfxdic[intdur]['step'])

	rrdcmd.append("CDEF:AVAIL1="+target+"AVAIL,0,20,LIMIT,UN,UNKN,INF,IF")
	rrdcmd.append("CDEF:AVAIL2="+target+"AVAIL,21,40,LIMIT,UN,UNKN,INF,IF")
	rrdcmd.append("CDEF:AVAIL3="+target+"AVAIL,39,79,LIMIT,UN,UNKN,INF,IF")
	rrdcmd.append("CDEF:AVAIL4="+target+"AVAIL,80,99,LIMIT,UN,UNKN,INF,IF")
	rrdcmd.append("CDEF:AVAIL5="+target+"AVAIL,100,100,LIMIT,UN,UNKN,INF,IF")

	rrdcmd.append('COMMENT:Availability\:')
	rrdcmd.append("AREA:AVAIL1#FF0000:0-20%")
	rrdcmd.append("AREA:AVAIL2#FFFF00:21-40%")
	rrdcmd.append("AREA:AVAIL3#FF8000:39-79%")
	rrdcmd.append("AREA:AVAIL4#00FFFF:80-99%")
	rrdcmd.append("AREA:AVAIL5#00FF00:100%")

	rrdcmd.append('LINE1:'+target+'AVRTT#0000ff:RTT latency ms')
	rrdcmd.append('GPRINT:'+target+'AVRTT:LAST:Current RTT\: %5.2lf ms')
	rrdcmd.append('GPRINT:'+target+'AVRTT:AVERAGE:Avg RTT\: %5.2lf ms')
	rrdcmd.append('GPRINT:'+target+'AVRTT:MAX:Max RTT\: %5.2lf ms')
	rrdcmd.append('GPRINT:'+target+'AVRTT:MIN:Min RTT\: %5.2lf ms')

	return rrdcmd

# -----------------------------------------------------------------------------
def gen_graphs(poldic, gfxdic):
	'''Generate graphs'''

	dbug(LINE)
	dbug('Spawn graph generation commands...')

	# Build command and launch each subprocess
	gfxprm_sort = OrderedDict(sorted(gfxdic.items(), key=lambda \
		x: int(x[1]['step'])))

	for target in sorted(poldic.keys()):
		for intvldur in gfxprm_sort:
			cmd = build_graph_command(poldic, gfxdic, target, intvldur)
			poldic[target][intvldur] = subprocess.Popen(cmd, \
				stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	# Wait for each child process to end
	for target in sorted(poldic.keys()):
		for intvldur in gfxprm_sort:
			poldic[target][intvldur].wait()

	# Read STDOUT and STDERR from each child process
	for target in sorted(poldic.keys()):
		for intvldur in gfxprm_sort:
			out, err = poldic[target][intvldur].communicate()
			#dbug(target, intvldur, poldic[target][intvldur].args)
			dbug(target, intvldur, "rrdtool graph STDOUT:", \
				out.decode('utf-8').replace('\n', ''))
			dbug(target, intvldur, "rrdtool graph STDERR:", \
				err.decode('utf-8').replace('\n', ''))

	# Clear PID, not JSON serializable (for dbug output)
	for target in sorted(poldic.keys()):
		for intvldur in gfxprm_sort:
			del poldic[target][intvldur]

	dbug('Graph generation complete')

# -----------------------------------------------------------------------------
def gen_html_index(poldic, gfxdic):
	'''Generate HTML '''

	idx = open(ARGS.htmldir+'/'+'mhag.html', 'w')
	idx.write('<!DOCTYPE html>\n')
	idx.write('<html>\n')
	idx.write('\t<head>\n')
	idx.write('\t\t<title>Multi Host Availability Grapher</title>\n')
	idx.write('\t\t<meta http-equiv="refresh" content="60">\n')
	idx.write('\t\t<meta http-equiv="cache-Control" content="no-cache">\n')
	idx.write('\t\t<meta http-equiv="pragma" content="no-cache">\n')
	one_min_from_now = datetime.now(timezone('UTC')) + timedelta(minutes=1)
	idx.write('\t\t<meta http-equiv="expires" content="' + \
		one_min_from_now.strftime("%c %Z")+'">\n')
	idx.write('\t\t<meta http-equiv="generator" content="MHAG '+VER+'">\n')
	idx.write('\t\t<meta http-equiv="date" content="' + \
		one_min_from_now.strftime("%c %Z")+'">\n')
	idx.write('\t\t<meta http-equiv="content-type" content="text/html;' + \
		' charset=iso-8859-15">')
	idx.write('\t\t<style type="text/css">\n')
	idx.write('\t\t</style>\n')

	idx.write('\t</head>\n')
	idx.write('<body>\n')
	idx.write('<h1>Multi Host Availability Grapher</h1>\n')

	idx.write('<table border=0 cellpadding=0 cellspacing=10>\n')

	gfxprm_sort = OrderedDict(sorted(gfxdic.items(), key=lambda \
		x: int(x[1]['step'])))

	for target in sorted(poldic.keys()):
		idx.write('<tr><td><div><b>'+target+'</b></div>')
		idx.write('<div><a href="'+target+'.html"><img border=1 \
			src="'+target+'1mx12h.png" title="1mx12h" \
			alt="1mx12h"></a><br></div></td></tr>\n')

		tgt = open(ARGS.htmldir+'/'+target+'.html', 'w')
		tgt.write('<!DOCTYPE html>\n')
		tgt.write('<html>\n')
		tgt.write('\t<head>\n')
		tgt.write('\t\t<title>Multi Host Availability Grapher - '+target+ \
			'</title>\n')
		tgt.write('\t\t<meta http-equiv="refresh" content="60">\n')
		tgt.write('\t\t<meta http-equiv="cache-control" content="no-cache">\n')
		tgt.write('\t\t<meta http-equiv="pragma" content="no-cache">\n')
		tgt.write('\t\t<meta http-equiv="expires" content="' + \
			one_min_from_now.strftime("%c %Z")+'">\n')
		tgt.write('\t\t<meta http-equiv="generator" content="MHAG ' + \
			VER+'">\n')
		tgt.write('\t\t<meta http-equiv="date" content="' + \
			one_min_from_now.strftime("%c %Z")+'">\n')
		tgt.write('\t\t<meta http-equiv="content-type" content="text/html;' + \
			' charset=iso-8859-15">')
		tgt.write(inline_style())
		tgt.write('\t</head>\n')
		tgt.write('\t<body>\n')
		tgt.write('\t\t<h1>Multi Host Availability Grapher - '+target+'</h1>\n')

		for intvldur in gfxprm_sort:
			dbug("graph name: "+ARGS.htmldir+target+intvldur+'.png')
			tgt.write('\t\t<div class="graph">')
			tgt.write('\t\t\t<h2>'+target+' ('+intvldur+')</h2>\n')
			tgt.write('<img src="'+target+intvldur+'.png" \
				title="'+intvldur+'" alt="'+intvldur+'">\n')
			tgt.write('\t\t</div>\n')

		tgt.write('\t<div align="right">')
		tgt.write('<a href="https://github.com/jullrey/MHAG/blob/master/LICENSE" target="MHAG License">')
		tgt.write('<i>MHAG License</i></a>')
		tgt.write('</div>\n')
		tgt.write('\t</body>\n')
		tgt.write('</html>\n')
		tgt.close()

	idx.write('</table>\n')
	idx.write('\t<div align="right">')
	idx.write('<a href="https://github.com/jullrey/MHAG/blob/master/LICENSE" target="MHAG License">')
	idx.write('<i>MHAG License</i></a>')
	idx.write('</div>\n')
	idx.write('</body>\n')
	idx.write('</html>\n')
	idx.close()

# -----------------------------------------------------------------------------
def inline_style():
	'''return the inline text/css style sheet'''
	multi_line = '''
		                <style type="text/css">
                        body {
                                background-color: #ffffff;
                        }
                        div {
                                border-bottom: 2px solid #aaa;
                                padding-bottom: 10px;
                                margin-bottom: 5px;
                        }
                        div h2 {
                                font-size: 1.2em;
                        }
                        div.graph img {
                                margin: 5px 0;
                        }
                        div.graph table, div#legend table {
                                font-size: .8em;
                        }
                        div.graph table td {
                                padding: 0 10px;
                                text-align: right;
                        }
                        div table .in th, div table td span.in {
                                color: #00cc00;
                        }
                        div table .out th, div table td span.out {
                                color: #0000ff;
                        }
                        div#legend th {
                                text-align: right;
                        }
                        div#footer {
                                border: none;
                                font-size: .8em;
                                font-family: Arial, Helvetica, sans-serif;
                                width: 476px;
                        }
                        div#footer img {
                                border: none;
                                height: 25px;
                        }
                        div#footer address {
                                text-align: right;
                        }
                        div#footer #version {
                                margin: 0;
                                padding: 0;
                                float: left;
                                width: 88px;
                                text-align: right;
                        }
                </style>
'''

	return multi_line

# -----------------------------------------------------------------------------
def dbug(*args, **kwargs):
	'''Pring Debugging info'''
	if ARGS.DEBUG:
		print("DEBUG: ", file=sys.stderr, end="")
		print(*args, file=sys.stderr, **kwargs, flush=True)

# -----------------------------------------------------------------------------
def parse_args():
	'''Process the command line arguments'''
	parser = argparse.ArgumentParser( \
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description='''Multi Host Availability Grapher
	Parse and format ping output to work with RRD (MRTG).''',
		epilog='''Example:
	/home/pi/bin/mhag.py -D /home/pi/data -H /var/www/html/graphs
	''')

	parser.add_argument('-d', '--debug', action='store_true', dest='DEBUG', \
		help='turn on debuging output')
	parser.add_argument('-c', '--comments', action='store_true', \
		dest='comments', \
		help='display the full documentation header of this script')
	parser.add_argument('-C', '--conf', dest='cfgfile', default='mhag.json', \
		help='cfg file name with .json extension (set path with -D)')
	parser.add_argument('-D', '--data', dest='datadir', default='', \
		help='directory to store database and default config file', \
		required=True)
	parser.add_argument('-H', '--html', dest='htmldir', default='', \
		help='directory to store html and graph files', \
		required=True)
	if len(sys.argv) == 1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	return parser.parse_args()
# -----------------------------------------------------------------------------
# --- END of function declarations --------------------------------------------
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# --- Required mechanism to start main() function -----------------------------
# -----------------------------------------------------------------------------
if __name__ == '__main__':
	ARGS = parse_args()
	main()

sys.exit() # exit program

	# Sample code to display exeptions
	#except Exception as ex:
	#	template = "An exception of type {0} occured. Arguments:\n{1!r}"
	#	message = template.format(type(ex).__name__, ex.args)
	#	print(message)

