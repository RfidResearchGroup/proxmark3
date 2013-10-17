local skel_1 = [[
<html>
<head>
	<style>
		* {
			background-color: #2F3440;
			background-color:#232323;
			color : #F5E5C0;
			text-transform: uppercase;
			font-size: 1.05em;
			font-family: monospace,Arial;
		}
		table{
			float:left;
			border: 1px solid white;
		}
		td{
			empty-cells : show;
		}
		td.blockzero {
			color: rgb(140, 245, 193);
		}
		td.key_a{
			color : #F8CA4D;
		}
		td.key_b{
			color : #3F5666;
		}
		td.accessconditions{
			color : #EA6045;
		}
	
		td.sectorhdr{
			border-top: 1px solid white;
		}
	</style>
	<script>
	function dc(x){return document.createElement(x)}

	function addClass(el, line, byte)
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


	function loadMifare(data)
	{
		var data = data.data;
		var t = dc("table")
		for(var i = 0 ; i < data.length ; i++)
		{
			line = data[i];
			var tr = dc("tr");
			t.appendChild(tr);
			addClass(tr,i);
			var bytes = line.match(/(.{1,2})/g);
			for(var b = 0 ; b < bytes.length ; b++)
				{
					var td  = dc('td');
					tr.appendChild(td);
					td.appendChild(document.createTextNode(bytes[b]));
					addClass(td,i,b);
				}
		}
		document.body.appendChild(t);
	}
	function to_ascii(hexval)
	{
		var intval = parseInt(hexval,16);
		if(intval > 31 && intval < 127)
		{
			return String.fromCharCode(intval);
		}
		return ".";
	}

	function loadAscii(data)
	{
		var data = data.data;
		var t = dc("table")
		for(var i = 0 ; i < data.length ; i++)
		{
			line = data[i];
			var tr = dc("tr");
			t.appendChild(tr);
			var bytes = line.match(/(.{1,2})/g);
			for(var b = 0 ; b < bytes.length ; b++)
			{
					var td  = dc('td');
					tr.appendChild(td);
					td.appendChild(document.createTextNode(to_ascii(bytes[b])))
					addClass(td,i,b);
			}
		}
		document.body.appendChild(t);
	}


	function load(data)
	{
		loadMifare(data);
		loadAscii(data);
	}
	</script>
	
</head>
<body>
</body>
<script>
	(function(){
		
		var x = {
			data : 
]]
local skel_2 = [[
			
		}
		load(x);
	})();
	</script>
</html>
]]
local function getHTML(data)
	return skel_1 .. data .. skel_2
end

return {getHTML = getHTML}
