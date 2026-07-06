package it.polito.mito.rest.spring;

import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import it.polito.mito.MitoSerializer;
import it.polito.mito.jaxb.NFV;

import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.ResponseHeader;

//mvn clean package && java -jar target\mito-0.0.1-SNAPSHOT.jar

// swagger can be accessed at http://localhost:8085/mito/swagger-ui.html 

@Controller
public class MitoController {
	
	
	@RequestMapping(method = RequestMethod.GET, value = "/")
	@ResponseBody
	public String infoMito() {
		return "<h1 style=\"color: #5e9ca0;\">MITO Spring Boot Rest APIs</h1>\r\n" + 
				"<h2>Available API:</h2>\r\n" + 
				"<ol>\r\n" + 
				"<li>&nbsp;POST an XML NFV document to /adp/simulations to run a simulation</li>\r\n" + 
				"<li>&nbsp;GET /adp/simulations/{id} to retrieve a stored simulation result</li>\r\n" + 
				"</ol>\r\n" + 
				"<h2 style=\"color: #2e6c80;\">How to use the Rest APIs:</h2>\r\n" + 
				"<p>You can read the Swagger documentation clicking <a href=\"./swagger-ui.html \">HERE</a>&nbsp;</p>\r\n" + 
				"<h2 style=\"color: #2e6c80;\">&nbsp;</h2>\r\n" + 
				"<p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;</p>";
	}


}
