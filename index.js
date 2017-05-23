/******************************
Filtra vulnerabilidades de nist del ultimo mes y con riesgo medio-alto.
Version 5/2017
Autor: Guillermo
*******************************/

//Carga de dependencias
const fs = require('fs');
//const download = require('download');
//const decompress = require('decompress');
var moment = require('moment');
moment().format();
//var https   = require('https');
//var unzip = require('unzip');

//Definicion de variables globales
var url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip";
var json1 = JSON.parse(fs.readFileSync('cve.json', 'utf8'));
var array = JSON.stringify(json1.CVE_Items);
var itera = 0;
var largo = json1.length;
var addResults = [];

//Inicio descarga de archivo
/*
download(url, 'vulns').then(() => {
    console.log('Descarga OK');
});
//download(url).pipe(fs.createWriteStream('./vulns/cve.zip'));

//Descomprime archio
fs.createReadStream('./vulns/cve.zip').pipe(unzip.Extract({ path: './vulns' }));
*/

//Del Json cargado desde el archivo en la variable json1, leo todos los objetos uno por uno en item:
for (var item of json1.CVE_Items) {
    itera = itera + 1; //Para conocer numero de objeto dentro del array
    if (typeof item.CVE_references.CVE_reference_data[0] !== 'undefined'){ //Para que no de error de undefined al leer el valor
    	if (item.CVE_references.CVE_reference_data[0].publish_date ){
     		var date = JSON.stringify(item.CVE_references.CVE_reference_data[0].publish_date); //Capturo fecha en formato dd/mm/yyyy
     		var day = date.slice(1, 3), month = date.slice(4, 6), year = date.slice(7, 11); //Capturo cada dato de la fecha por separado
     		//Utilizo moment.js para comparar fechas
     		var now = moment();
     		var publishDate = moment(year+'-'+month+'-'+day); //Lo paso al formato que acepta moment.js para comparar fechas
     		var howFar = publishDate.fromNow(true); //Le pregunto a moment.js cuantos dias/meses pasaron desde la fecha en cuestion, devuelve un string
     		var substring2 = "a month"; //String que se va a buscar
     		var substring3 = "days";
     		if ( howFar.indexOf(substring2) > -1 || howFar.indexOf(substring3) > -1){
		    	//El if evalua si ALGUNO de los strings se encuentran en howFar, asi tenemos los que tienen menos de 30 dias y 1 mes exactos desde la fecha
		    	// LLAMAR A FUNCION FILTRO DE RIESGO (risk_filter) pasando el dato del numero de iteracion
		    	if( typeof item.CVE_impact.CVE_impact_cvssv3.bm !== 'undefined' ){ //Si el valor cvss v3 esta definido evalua su score mayor a 4
		    		if (item.CVE_impact.CVE_impact_cvssv3.bm.score > 4){
		    			//Agregar resultados personalizados a mi array llamado addResults
		    			//Cargo los resultados en el array addResults que sera el mostrado al final como resultado
		    			addResults.push({"id":json1.CVE_Items[itera].CVE_data_meta.CVE_ID, //Meto objetos dentro del array
		    				"description":json1.CVE_Items[itera].CVE_description.CVE_description_data[0].value,
		    							//"risk":json1.CVE_Items[itera].CVE_impact.CVE_impact_cvssv3.bm.score,
		    							//"corp":json1.CVE_Items[itera].CVE_affects.CVE_vendor.CVE_vendor_data[0].CVE_vendor_name,
		    							"references":json1.CVE_Items[itera].CVE_references
		    						}); 
		    		} else if ( typeof item.CVE_affects.CVE_vendor.CVE_vendor_data[0] !== 'undefined' ){ //Ademas evaluar en la descripcion
		    			var corps = ['microsoft','linux','oracle','apache','iis','redhat']; //Evalua si encuentra fabricantes conocidos sin evaluar el riesgo 
		    			for (var itcorp of corps) {
		    				if (item.CVE_affects.CVE_vendor.CVE_vendor_data[0].CVE_vendor_name == itcorp || item.CVE_description.CVE_description_data[0].value.indexOf(itcorp) > -1){
		    					console.log('Fabricante:', JSON.stringify(item));
		    	     		addResults.push({"id":json1.CVE_Items[itera].CVE_data_meta.CVE_ID, //Meto objetos dentro del array
		    	     			"description":json1.CVE_Items[itera].CVE_description.CVE_description_data[0].value,
		    							//"risk":json1.CVE_Items[itera].CVE_impact.CVE_impact_cvssv3.bm.score,
		    							"references":json1.CVE_Items[itera].CVE_references
		    						});
	    	     	  }
	    	      }    	     	
	    	    }
	        }
	        //Para los que no tengan impacto, igual analizar los fabricantes

	        if ( typeof item.CVE_affects.CVE_vendor.CVE_vendor_data[0] !== 'undefined' ){ //Ademas evaluar en la descripcion
		    			var corps = ['microsoft','linux','oracle','apache','iis','redhat']; //Evalua si encuentra fabricantes conocidos sin evaluar el riesgo 
		    			for (var itcorp of corps) {
		    				if (item.CVE_affects.CVE_vendor.CVE_vendor_data[0].CVE_vendor_name == itcorp ){
		    					//console.log(itcorp + ' ' + item.CVE_affects.CVE_vendor.CVE_vendor_data[0].CVE_vendor_name + item.CVE_data_meta.CVE_ID);
		    					//console.log('Fabricante:', JSON.stringify(item));
		    	     		addResults.push({"id":json1.CVE_Items[itera].CVE_data_meta.CVE_ID, //Meto objetos dentro del array
		    	     				"description":json1.CVE_Items[itera].CVE_description.CVE_description_data[0].value,
		    							//"risk":json1.CVE_Items[itera].CVE_impact.CVE_impact_cvssv3.bm.score,
		    							"references":json1.CVE_Items[itera].CVE_references
		    						});
	    	     	  }
	    	      }    	     	
	    	    }
	    	    
	      }    	
	    }     	
	  }   
}

//Rearmar json con solamente los datos interesantes y en nuestro formato, para luego mostrar en la web con html (hay que servir un punto de acceso a una api local para que JS lo tome)

var resultadoFinal = JSON.stringify(addResults);
//console.log(resultadoFinal); //muestra el final y lo guarda en un archivo local, luego ese puede ser tomado por un html para mostrarse o alterarse
fs.writeFile('myjsonfile.json', resultadoFinal, 'utf8');

// PSEUDOCODIGO
/*
//Cargo archivo de json a variable, cargar solamente array que nos interesa: CVE_Items
//Para cada objeto del array solamente dejar los de riesgo CVSSv3 mayores a 4  //CVE_impact > CVE_impact_cvssv3 > score

//Hacer un grep de sistemas y aplicaciones (habra que seleccionar a que cliente corresponde el boletin para saber que lista de aplicaciones tomar)

//Variable json con resultados finales para mostrar en tabla html
/******************************
Descargar json desde https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip
Descomprimir
Filtrar solo los de riesgo cvss mayor a 4 - CVE_impact - CVE_impact_cvssv3 - score
Filtrar los del último mes - CVE_references - CVE_reference_data(0) - publish_date
Filtrar los que podrian impactar en sistemas del cliente
Mostrar resultados en tabla html
*******************************/