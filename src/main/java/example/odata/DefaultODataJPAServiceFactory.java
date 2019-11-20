package example.odata;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.persistence.EntityManager;

import org.apache.olingo.odata2.jpa.processor.api.ODataJPAContext;
import org.apache.olingo.odata2.jpa.processor.api.ODataJPAServiceFactory;
import org.apache.olingo.odata2.jpa.processor.api.exception.ODataJPARuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class DefaultODataJPAServiceFactory extends ODataJPAServiceFactory {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultODataJPAServiceFactory.class);

    @Inject
    private EntityManager em;

    @Override
    public ODataJPAContext initializeODataJPAContext() throws ODataJPARuntimeException {
        ODataJPAContext ctx = getODataJPAContext();
        //ODataContext octx = ctx.getODataContext();
        //HttpRequest request = (HttpRequest) octx.getParameter(
        //  ODataContext.HTTP_SERVLET_REQUEST_OBJECT);
        //EntityManager em = (EntityManager) request
        // .getAttribute(EntityManagerFilter.EM_REQUEST_ATTRIBUTE);
         
        ctx.setEntityManager(em);
        ctx.setPersistenceUnitName("default");
        ctx.setContainerManaged(true);                
        return ctx;
    }
} 