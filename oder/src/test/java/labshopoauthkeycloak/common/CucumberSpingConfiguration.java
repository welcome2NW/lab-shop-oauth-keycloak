package labshopoauthkeycloak.common;

import io.cucumber.spring.CucumberContextConfiguration;
import labshopoauthkeycloak.OderApplication;
import org.springframework.boot.test.context.SpringBootTest;

@CucumberContextConfiguration
@SpringBootTest(classes = { OderApplication.class })
public class CucumberSpingConfiguration {}
