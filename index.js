//Carga de dependencias
const fs = require('fs');
const download = require('download');
const decompress = require('decompress');
//var https   = require('https');
//var unzip = require('unzip');
var moment = require('moment');
moment().format();

//Definicion de variables
var url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip";
//Inicio descarga de archivo
/*
download(url, 'vulns').then(() => {
    console.log('Descarga OK');
});
//download(url).pipe(fs.createWriteStream('./vulns/cve.zip'));

//Descomprime archio
fs.createReadStream('./vulns/cve.zip').pipe(unzip.Extract({ path: './vulns' }));
*/

var json1 = JSON.parse(fs.readFileSync('cve.json', 'utf8'));
var array = JSON.stringify(json1.CVE_Items);
var itera = 0;
var largo = json1.length;

for (var item of json1.CVE_Items) {
    //console.log('item: ', JSON.stringify(item));
    //Utilizar moment.js para comparar fechas
    //var str = '04/17/2017';
	//var res = str.slice(0, 2);
	//console.log(res);

	itera = itera + 1;
    if (typeof item.CVE_references.CVE_reference_data[0] !== 'undefined'){
     	if (item.CVE_references.CVE_reference_data[0].publish_date ){
     		var date = JSON.stringify(item.CVE_references.CVE_reference_data[0].publish_date);
     		//console.log('Fecha:', date);
     		var day = date.slice(1, 3), month = date.slice(4, 6), year = date.slice(7, 11);
     		//console.log('Fecha:', day + month + year );

     		var now = moment();
     		var publishDate = moment(year+'-'+month+'-'+day);
     		var howFar = publishDate.fromNow(true);
     		//console.log(howFar);
		    
		    var substring2 = "a month";
		    if ( howFar.indexOf(substring2) > -1 ){
		    	//console.log(itera + '2 ' + howFar);
		    	// LLAMAR A FUNCION FILTRO DE RIESGO (risk_filter) pasando el dato del numero de iteracion
		    	if( typeof item.CVE_impact.CVE_impact_cvssv3.bm !== 'undefined' ){
		    		if (item.CVE_impact.CVE_impact_cvssv3.bm.score > 4){
		    			console.log('Riesgo: ', JSON.stringify(json1.CVE_Items[itera]));
		    			//console.log('Riesgo:', JSON.stringify(item.CVE_impact.CVE_impact_cvssv3.bm.score));
		    		}     	
		    	}
		    	//json1.splice(itera,1);
		    	/*if ( json1.CVE_Items[itera] ){ 
		    		console.log('esta');
		    	    //array.splice(itera,1);
		    	    //console.log('4 ' + json1.CVE_Items[itera]);
		    	}*/
		    }
		    var substring2 = "days";
		    if ( howFar.indexOf(substring2) > -1 ){
		    	//console.log(itera + '3 ' + howFar);
		    	console.log('Total: ', JSON.stringify(json1.CVE_Items[itera]));
		    	// LLAMAR A FUNCION FILTRO DE RIESGO (risk_filter) pasando el dato del numero de iteracion
		    	if( typeof item.CVE_impact.CVE_impact_cvssv3.bm !== 'undefined' ){
		    		if (item.CVE_impact.CVE_impact_cvssv3.bm.score > 4){
		    			//console.log('Risk');
		    			console.log('Riesgo: ', JSON.stringify(json1.CVE_Items[itera]));
		    			//console.log('Riesgo:', JSON.stringify(item.CVE_impact.CVE_impact_cvssv3.bm.score));
		    		}     	
		    	}
		    }

		         /*
		         if ( typeof item.CVE_affects.CVE_vendor.CVE_vendor_data[0] !== 'undefined' ){
		         	var corps = ['microsoft','linux','oracle','apache','','redhat'];
		         	for (var itcorp of corps) {
		         		if (item.CVE_affects.CVE_vendor.CVE_vendor_data[0].CVE_vendor_name = itcorp){
		    	     		console.log('Fabricante:', JSON.stringify(item));
		    	     	}
		         	}    	     	
		         }
		         */
		     
		      

		    /*
     		var substring = "Invalid";
     		if (howFar.indexOf(substring) > -1){
     			console.log('2 ' + howFar);
			}
     		*/

     		//if (publishDate.fromNow(true) )
     		//'months' 'invalid'
     		/*
			var futureMonth = moment(publishDate).add(1, 'M');
			var futureMonthEnd = moment(futureMonth).endOf('month');
			*/
			/*
			if(publishDate.date() != futureMonth.date() && futureMonth.isSame(futureMonthEnd.format('YYYY-MM-DD'))) {
			    futureMonth = futureMonth.add(1, 'd');
			}
			*/
     	}     	
    }   
}
/*
for(var exKey in obj) {
      console.log("key:"+exKey+", value:"+exjson[exKey]);
 }
 
 

console.log(obj);
*/
/*
//Cargo archivo de json a variable, cargar solamente array que nos interesa: CVE_Items
//Para cada objeto del array solamente dejar los de riesgo CVSSv3 mayores a 4  //CVE_impact > CVE_impact_cvssv3 > score

//Hacer un grep de sistemas y aplicaciones (habra que seleccionar a que cliente corresponde el boletin para saber que lista de aplicaciones tomar)

//Variable json con resultados finales para mostrar en tabla html
/******************************
Pseudocodigo: Descargar json desde https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip
Descomprimir
Filtrar solo los de riesgo cvss mayor a 4 - CVE_impact - CVE_impact_cvssv3 - score
Filtrar los del último mes - CVE_references - CVE_reference_data(0) - publish_date
Filtrar los que podrian impactar en sistemas del cliente
Mostrar resultados en tabla html

Agregar aplicaciones a la chdm !
Rodrigo va a tomar lista de aplicaciones utilizadas en Sistar para luego hacer grep contra la lista de vulnerabilidades.
*******************************/