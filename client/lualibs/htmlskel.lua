local skel_1 = [[
<html>
<head>

	<script>
		var dictionary =  {}
		function add(commaSeparated)
		{
			var fields = commaSeparated.split(",");
			var manufacturerCode = fields[0];
			var modelCode 	= fields[1];
			var modelSubCode= fields[2];
			var modelName 	= fields[3]; 
			var ATQA 		= fields[4];
			var SAK 		= fields[5];

			//In the data below, wrong endian is used. Mifare is 
			// written as "0004" instead of "0400", so we need to 
			// flip it
			ATQA = ATQA.substr(2,4)+ATQA.substr(0,2)

			var info = {
				modelCode : modelCode, 
				modelSubCode : modelSubCode,
				modelName : modelName,
				ATQA 	: ATQA, 
				SAK 	: SAK
			}
			console.log("Adding "+modelName+" , "+SAK)

			dictionary[ATQA] = dictionary[ATQA] || [];
			dictionary[ATQA].push(info)
		}
		function lookup(atqa, sak)
		{
			if (!dictionary[atqa]) return "UNKNOWN";

			var possibleMatches = [];
			for(var i = 0 ; i < dictionary[atqa].length ; i++)
			{

				var info = dictionary[atqa][i];
				console.log("Comparing "+sak+ " with "+ info.SAK);
				if(sak && info.SAK == sak)//exact match
				{
					return info.modelName;
//					possibleMatches.push(info.modelName);
				}else //SAK unknown
				{
					possibleMatches.push(info.modelName);
				}
			}
			if(possibleMatches.length > 0)
				return possibleMatches.join(" or ");
			return "UNKNOWN"
		}

		add("04,,,Mifare TNP3xxx Activision 1K,0f01,01");
		add("04,,,Mifare Mini,0004,09");
		add("04,,,Mifare Classic 1k/Mifare Plus(4 byte UID) 2K SL1,0004,08");
		add("04,,,Mifare Plus (4 byte UID) 2K SL2,0004,10");
		add("04,,,Mifare Plus (4 byte UID) 4K SL2,0004,11");
		add("04,,,Mifare Plus (4 byte UID) 4K SL1,0004,18");
		add("04,,,Mifare Plus (4 byte UID) 2K/4K SL3,0004,20");
		add("04,,,Mifare Classic 4K,0002,18");
		add("xx,,,NDEF Tags,0044,00  ");
		add("04,,,Mifare Ultralight/UltralightC,0044,04");
		add("04,,,Mifare Plus (7 byte UID) 2K SL1,0042,08");
		add("04,,,Mifare Plus (7 byte UID) 2K SL1,0044,08");
		add("04,,,Mifare Plus (7 byte UID) 4K SL1,0042,18");
		add("04,,,Mifare Plus (7 byte UID) 4K SL1,0044,18");
		add("04,,,Mifare Plus (7 byte UID),0042,10");
		add("04,,,Mifare Plus (7 byte UID),0044,10");
		add("04,,,Mifare Plus (7 byte UID),0042,11");
		add("04,,,Mifare Plus (7 byte UID),0044,11");
		add("04,,,Mifare Plus (7 byte UID),0042,20");
		add("04,,,Mifare Plus (7 byte UID),0044,20");
		add("04,,,Mifare DesFire / DesFire EV1,0344,20067577810280");
		add("04,,,JCOP31,0304,283877B14A434F503331");
		add("04,,,JCOP31 v2.4.1,0048,207877B1024A434F5076323431");
		add("04,,,JCOP41 v2.2,0048,203833B14A434F503431563232");
		add("04,,,JCOP41 v2.3.1,0004,283833B14A434F50343156323331");
		add("05,,,Mifare Classic 1K,0004,88");
		add("40,,,MPCOS,0002,98");
		add("25,,,Topaz/Topaz512/Jewel,0C00,");
		add("1D,,,FM1208SH01,0004,53");
		add("1D,,,FM1208,0008,20");
		add("Nokia,,,Mifare Classic 4K emulated by Nokia 6212,0002,38");
		add("Nokia,,,Mifare Classic 4K emulated by Nokia 6131,0008,38");
		add("04,,,Smart MX with Mifare 4K emulation,0002");
		add("04,,,Smart MX with Mifare 4K emulation,0102");
		add("04,,,Smart MX with Mifare 4K emulation,0202");
		add("04,,,Smart MX with Mifare 4K emulation,0302");
		add("04,,,Smart MX with Mifare 4K emulation,0402");
		add("04,,,Smart MX with Mifare 4K emulation,0502");
		add("04,,,Smart MX with Mifare 4K emulation,0602");
		add("04,,,Smart MX with Mifare 4K emulation,0702");
		add("04,,,Smart MX with Mifare 4K emulation,0802");
		add("04,,,Smart MX with Mifare 4K emulation,0902");
		add("04,,,Smart MX with Mifare 4K emulation,0A02");
		add("04,,,Smart MX with Mifare 4K emulation,0B02");
		add("04,,,Smart MX with Mifare 4K emulation,0C02");
		add("04,,,Smart MX with Mifare 4K emulation,0D02");
		add("04,,,Smart MX with Mifare 4K emulation,0E02");
		add("04,,,Smart MX with Mifare 4K emulation,0F02");
		add("04,,,Smart MX with Mifare 1K emulation,0004");
		add("04,,,Smart MX with Mifare 1K emulation,0104");
		add("04,,,Smart MX with Mifare 1K emulation,0204");
		add("04,,,Smart MX with Mifare 1K emulation,0304");
		add("04,,,Smart MX with Mifare 1K emulation,0404");
		add("04,,,Smart MX with Mifare 1K emulation,0504");
		add("04,,,Smart MX with Mifare 1K emulation,0604");
		add("04,,,Smart MX with Mifare 1K emulation,0704");
		add("04,,,Smart MX with Mifare 1K emulation,0804");
		add("04,,,Smart MX with Mifare 1K emulation,0904");
		add("04,,,Smart MX with Mifare 1K emulation,0A04");
		add("04,,,Smart MX with Mifare 1K emulation,0B04");
		add("04,,,Smart MX with Mifare 1K emulation,0C04");
		add("04,,,Smart MX with Mifare 1K emulation,0D04");
		add("04,,,Smart MX with Mifare 1K emulation,0E04");
		add("04,,,Smart MX with Mifare 1K emulation,0F04");
		add("04,,,Smart MX with 7 byte UID,0048");
		add("04,,,Smart MX with 7 byte UID,0148");
		add("04,,,Smart MX with 7 byte UID,0248");
		add("04,,,Smart MX with 7 byte UID,0348");
		add("04,,,Smart MX with 7 byte UID,0448");
		add("04,,,Smart MX with 7 byte UID,0548");
		add("04,,,Smart MX with 7 byte UID,0648");
		add("04,,,Smart MX with 7 byte UID,0748");
		add("04,,,Smart MX with 7 byte UID,0848");
		add("04,,,Smart MX with 7 byte UID,0948");
		add("04,,,Smart MX with 7 byte UID,0A48");
		add("04,,,Smart MX with 7 byte UID,0B48");
		add("04,,,Smart MX with 7 byte UID,0C48");
		add("04,,,Smart MX with 7 byte UID,0D48");
		add("04,,,Smart MX with 7 byte UID,0E48");
		add("04,,,Smart MX with 7 byte UID,0F48");	
</script>

	<style>
		* {
			background-color: #2F3440;
			background-color:#232323;
			color : #F5E5C0;
			xtext-transform: uppercase;
			font-size: 1.05em;
			font-family: monospace,Arial;
		}
		table{
			float:left;
			border: 1px solid white;
		}
		td {
			empty-cells: show;
		}
		td.blockzero, .turqoise{
			color: rgb(140, 245, 193);
		}
		td.key_a, .yellow{
			color : #F8CA4D;
		}
		td.key_b, .blue{
			color : #3F5666;
		}
		td.accessconditions, .red{
			color : #EA6045;
		}
	
		td.sectorhdr{
			border-top: 1px solid white;
		}
	</style>
	<script>
	/** Jquery for the poor **/
	function dc(x){return document.createElement(x)}

	function tr(table){
		var row = dc('tr');
		table.appendChild(row);
		return row;
	}
	function td(row, text){
		var tdata = dc('td');
		row.appendChild(tdata);
		tdata.appendChild(document.createTextNode(text))
		return tdata;
	}

	/**
	* The identifiers that determine how to highlight data and present information
	**/
	var identifiers = [
		function(data)
		{
			// Should be 32 characters long ( 16 bytes per block)
			if(data[0].length != 32) { return false; }
			// ... add more checks if necessary ... 

			var info = {Type : "Mifare"}
			info['Size'] = (data[0].length / 2 * data.length) + " Bytes";
			info['UID'] = data[0].substring(0,8);
			info['SAK'] = data[0].substring(10,12);
			info['ATQA'] = data[0].substring(12,16);

			info['Name'] = lookup(info.ATQA, info.SAK);
			return {info: info, highlighter : mifareHighlighter }
		},
		function(data)
		{
			// Should be 8 characters long ( 4 bytes per block)
			if(data[0].length != 8) { return false; }
			// ... add more checks if necessary ... 
			var info = {Type : "NDEF"}
			info['Size'] = (data[0].length / 2 * data.length) + " Bytes";

			return {info: info, highlighter : ndefHighligheter }
		}, 
		function(data)
		{//This is the catch-all
			return {info: {type : "Unknown"}, highlighter : noHighlighter}
		}
	]
	

	/**
	* Helper function to convert bin-data into printable chars
	**/

	function to_ascii(hexval)
	{
		var intval = parseInt(hexval,16);
		if(intval > 31 && intval < 127)
		{
			return String.fromCharCode(intval);
		}
		return ".";
	}


	function loadIntoTable(data, info, ascii)
	{
		var t = dc("table")
		for(var i = 0 ; i < data.length ; i++)
		{
			line = data[i];
			var row = tr(t);
			var bytes = line.match(/(.{1,2})/g);
			for(var b = 0 ; b < bytes.length ; b++)
			{
					var elem = td(row, ascii ? to_ascii(bytes[b]) : bytes[b]);
					info.highlighter.addClass(elem,i,b, bytes[b]);
			}
		}
		document.body.appendChild(t);
	}
	function loadGeneralInfo(data, info)
	{
		var t = dc("table");
		for (var key in info)
		{
			var row = tr(t);
			td(row,key);
			td(row,info[key]);			
		}
		document.body.appendChild(t);
	}

	function handle(dump)
	{
		var data = dump.data;
		var info = null;
		for(var i = 0; i < identifiers.length && !info; i++)
			info = identifiers[i](data);

		console.log(info);

		loadIntoTable(data, info, false);
		loadIntoTable(data, info, true);
		loadGeneralInfo(data, info.info);

	}
	var noHighlighter = {
		addClass : function(el ,line, byte)
		{
			return;
		}
	};
	var ndefHighligheter = {
		addClass : function(el ,line, byte, value)
		{
			if(line  < 3)
			{
				el.className += " red";
			}
			if ( line == 3)
			{
				console.log(value);
				if( byte == 0 && "e1" == value.toLowerCase())	el.className += " turqoise";
				if( byte == 1 )	el.className += " yellow";
				if( byte == 2 )	el.className += " blue";
				return;
			}
		}
	};
	var mifareHighlighter = {
		addClass : function(el ,line, byte)
		{
			if (line == 0)
			{
				el.className += " blockzero";
			}
			
			if(line < 128){
				linesPerSector = 4;
			}else
			{
				//Quadruple size sectors
				linesPerSector = 16;
				line = line - 128;

			}

			if(line % linesPerSector == 0)
			{
				el.className += " sectorhdr";
			}
			if(line % linesPerSector == (linesPerSector -1))
			{
				el.className += " sectortrailer";
				if(byte == undefined)
				{
					return;
				}		

				if(byte < 6) el.className += " key_a";
				else if(byte < 10) el.className += " accessconditions";
				else el.className += " key_b";
			}

		}
	};



	</script>
	
</head>
<body></body>
<script>
	var x = { data : 
]]
local skel_2 = [[
			
		};
	handle(x);
	</script>
</html>

]]
local function getHTML(data)
	return skel_1 .. data .. skel_2
end

return {getHTML = getHTML}
