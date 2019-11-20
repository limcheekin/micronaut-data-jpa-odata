package example.controllers;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import javax.inject.Inject;

import org.apache.olingo.odata2.api.ODataService;
import org.apache.olingo.odata2.api.ODataServiceFactory;
import org.apache.olingo.odata2.api.commons.ODataHttpMethod;
import org.apache.olingo.odata2.api.exception.MessageReference;
import org.apache.olingo.odata2.api.exception.ODataBadRequestException;
import org.apache.olingo.odata2.api.exception.ODataHttpException;
import org.apache.olingo.odata2.api.exception.ODataInternalServerErrorException;
import org.apache.olingo.odata2.api.exception.ODataMethodNotAllowedException;
import org.apache.olingo.odata2.api.exception.ODataNotAcceptableException;
import org.apache.olingo.odata2.api.exception.ODataNotImplementedException;
import org.apache.olingo.odata2.api.processor.ODataContext;
import org.apache.olingo.odata2.api.processor.ODataRequest;
import org.apache.olingo.odata2.api.processor.ODataResponse;
import org.apache.olingo.odata2.core.ODataContextImpl;
import org.apache.olingo.odata2.core.ODataRequestHandler;
import org.apache.olingo.odata2.core.exception.ODataRuntimeException;
import org.apache.olingo.odata2.core.rest.ODataExceptionWrapper;
import org.apache.olingo.odata2.core.servlet.RestUtil;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;

@Controller("/odata")
public class ODataController {
    private static final String HTTP_METHOD_OPTIONS = "OPTIONS";
    private static final String HTTP_METHOD_HEAD = "HEAD";

    /**
     * Label used in web.xml to assign servlet init parameter for a path split
     * (service resolution).
     */
    private static final String BUFFER_SIZE = "org.apache.olingo.odata2.core.servlet.buffer.size";
    private static final int DEFAULT_BUFFER_SIZE = 32768;
    private static final String DEFAULT_READ_CHARSET = "utf-8";

    @Inject
    private ODataServiceFactory serviceFactory;
    
    final String pathSplitAsString = getInitParameter(ODataServiceFactory.PATH_SPLIT_LABEL);
    final String formEncoding = getInitParameter(ODataServiceFactory.ACCEPT_FORM_ENCODING);

    String getInitParameter(String param) {
        return null;
    }
    
    @Get
    public HttpResponse<?> index(HttpRequest<?> request) {
        if (serviceFactory == null) {
            throw new ODataRuntimeException(
                    "Unable to get Service Factory. Check either '" + ODataServiceFactory.FACTORY_LABEL + "' or '"
                            + ODataServiceFactory.FACTORY_INSTANCE_LABEL + "' config.");
        }
        Properties headers = request.getHeaders().asProperties();
        String xHttpMethod = headers.getProperty("X-HTTP-Method");
        String xHttpMethodOverride = headers.getProperty("X-HTTP-Method-Override");
        if (xHttpMethod != null && xHttpMethodOverride != null) {
            if (!xHttpMethod.equalsIgnoreCase(xHttpMethodOverride)) {
                return HttpResponse.badRequest(new ODataBadRequestException(ODataBadRequestException.AMBIGUOUS_XMETHOD));
            }
        }
        try {
            if (request.getPath() != null) {
                return handle(request, xHttpMethod, xHttpMethodOverride);
            } else {
                //handleRedirect(request);
            }
        } catch (Exception e) {
            throw new ODataRuntimeException(e);
        }

        return HttpResponse.serverError();
    }

    private HttpResponse<?> handle(final HttpRequest<?> request, final String xHttpMethod, final String xHttpMethodOverride) throws Exception {
        String method = request.getMethod().name(); 

        if (ODataHttpMethod.GET.name().equals(method)) {
            return handleRequest(request, ODataHttpMethod.GET);
        } else if (ODataHttpMethod.POST.name().equals(method)) {
            if (xHttpMethod == null && xHttpMethodOverride == null) {
                return handleRequest(request, ODataHttpMethod.POST);
            } else if (xHttpMethod == null) {
                /* tunneling */
                return handleHttpTunneling(request, xHttpMethodOverride);
                /*if (!methodHandled) {
                    return createMethodNotAllowedResponse(request, ODataHttpException.COMMON);
                }*/
            } else {
                /* tunneling */
                return handleHttpTunneling(request, xHttpMethod);
                /*if (!methodHandled) {
                    createNotImplementedResponse(request, ODataNotImplementedException.TUNNELING, resp, serviceFactory);
                }*/
            }

        } else if (ODataHttpMethod.PUT.name().equals(method)) {
            return handleRequest(request, ODataHttpMethod.PUT);
        } else if (ODataHttpMethod.DELETE.name().equals(method)) {
            return handleRequest(request, ODataHttpMethod.DELETE);
        } else if (ODataHttpMethod.PATCH.name().equals(method)) {
            return handleRequest(request, ODataHttpMethod.PATCH);
        } else if (ODataHttpMethod.MERGE.name().equals(method)) {
            return handleRequest(request, ODataHttpMethod.MERGE);
        } else if (HTTP_METHOD_HEAD.equals(method)) {
            return handleRequest(request, ODataHttpMethod.GET);
        } else if (HTTP_METHOD_OPTIONS.equals(method)) {
            return HttpResponse.notAllowed(HttpMethod.OPTIONS);
        } else {
            return HttpResponse.notAllowed(HttpMethod.valueOf(method));
        }
    }

    private HttpResponse<?> handleHttpTunneling(final HttpRequest<?> request, final String xHttpMethod) throws Exception {
        if (ODataHttpMethod.MERGE.name().equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.MERGE);
        } else if (ODataHttpMethod.PATCH.name().equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.PATCH);
        } else if (ODataHttpMethod.DELETE.name().equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.DELETE);
        } else if (ODataHttpMethod.PUT.name().equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.PUT);
        } else if (ODataHttpMethod.GET.name().equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.GET);
        } else if (HTTP_METHOD_HEAD.equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.GET);
        } else if (ODataHttpMethod.POST.name().equals(xHttpMethod)) {
            return handleRequest(request, ODataHttpMethod.POST);
        } else if (HTTP_METHOD_OPTIONS.equals(xHttpMethod)) {
            return HttpResponse.notAllowed(HttpMethod.OPTIONS);
        } else {
            return HttpResponse.notAllowed(HttpMethod.valueOf(xHttpMethod));
        }
    }

    private HttpResponse<?> handleRequest(final HttpRequest<?> request, final ODataHttpMethod method) throws Exception {
        try {
            int pathSplit = 0;
            if (pathSplitAsString != null) {
                pathSplit = Integer.parseInt(pathSplitAsString);
            }

            Properties headers = request.getHeaders().asProperties();
            ODataRequest odataRequest;
            try {
                odataRequest = ODataRequest.method(method).httpMethod(request.getMethod().name())
                        .contentType(request.getContentType().get().getName())
                        .acceptHeaders(request.getHeaders().accept().stream().map(MediaType::getName).collect(Collectors.toList()))
                        .acceptableLanguages(RestUtil.extractAcceptableLanguage(headers.getProperty(HttpHeaders.ACCEPT_LANGUAGE)))
                        //.pathInfo(RestUtil.buildODataPathInfo(request, pathSplit))
                        .allQueryParameters(request.getParameters().asMap())
                        .requestHeaders(request.getHeaders().asMap()).body(request.getBody(InputStream.class).get())
                        .build();
            } catch (IllegalArgumentException e) {
                throw new ODataBadRequestException(ODataBadRequestException.INVALID_REQUEST, e);
            }
    
            ODataContextImpl context = new ODataContextImpl(odataRequest, serviceFactory);
            context.setParameter(ODataContext.HTTP_SERVLET_REQUEST_OBJECT, request);

            if (headers.getProperty(HttpHeaders.ACCEPT) != null && headers.getProperty(HttpHeaders.ACCEPT).isEmpty()) {
                return createNotAcceptableResponse(getODataExceptionWrapper(context, request), ODataNotAcceptableException.COMMON);
            }

            ODataService service = serviceFactory.createService(context);
            if (service == null) {
                return createServiceUnavailableResponse(getODataExceptionWrapper(context, request), ODataInternalServerErrorException.NOSERVICE);
            } else {
                context.setService(service);
                service.getProcessor().setContext(context);

                ODataRequestHandler requestHandler = new ODataRequestHandler(serviceFactory, service, context);
                final ODataResponse odataResponse = requestHandler.handle(odataRequest);
                //
                boolean omitResponseBody = HTTP_METHOD_HEAD.equals(request.getMethod().name());
                return createResponse(odataResponse, omitResponseBody);
            }
        } catch (Exception e) {
            throw e;
        }
    }

    /*protected HttpResponse<?> handleRedirect(final HttpRequest<?> request, final HttpServletResponse resp,
            ODataServiceFactory serviceFactory) throws IOException {
        String method = request.getMethod().name();
        if (ODataHttpMethod.GET.name().equals(method) || ODataHttpMethod.POST.name().equals(method)
                || ODataHttpMethod.PUT.name().equals(method) || ODataHttpMethod.DELETE.name().equals(method)
                || ODataHttpMethod.PATCH.name().equals(method) || ODataHttpMethod.MERGE.name().equals(method)
                || HTTP_METHOD_HEAD.equals(method) || HTTP_METHOD_OPTIONS.equals(method)) {
            ODataResponse odataResponse = ODataResponse.status(HttpStatusCodes.TEMPORARY_REDIRECT)
                    .header(HttpHeaders.LOCATION, createLocation(req)).build();
            createResponse(resp, odataResponse);
        } else {
            createNotImplementedResponse(request, ODataHttpException.COMMON, resp, serviceFactory);
        }

    }

    private String createLocation(final HttpRequest<?> req) {
        StringBuilder location = new StringBuilder();
        String contextPath = request.getContextPath();
        if (contextPath != null) {
            location.append(contextPath);
        }
        String servletPath = request.getServletPath();
        if (servletPath != null) {
            location.append(servletPath);
        }
        location.append("/");
        return location.toString();
    }*/

    protected HttpResponse<?> createResponse(final ODataResponse response) throws IOException {
        return createResponse(response, false);
    }

    protected HttpResponse<?> createResponse(final ODataResponse response,
            final boolean omitResponseBody) throws IOException {
        Map<CharSequence,CharSequence> headers = new HashMap<>(response.getHeaderNames().size());
        for (String headerName : response.getHeaderNames()) {
            headers.put(headerName, response.getHeader(headerName));
        }
        
        if (omitResponseBody) {
            return HttpResponse.status(HttpStatus.valueOf(response.getStatus().getStatusCode()))
            .contentType(response.getContentHeader())
            .headers(headers);
        } 

        Object entity = response.getEntity();
        if (entity != null) {
            if (entity instanceof InputStream) {
                final byte[] body = handleStream((InputStream) entity);
                return HttpResponse.status(HttpStatus.valueOf(response.getStatus().getStatusCode()))
                .contentType(response.getContentHeader())
                .headers(headers)
                .contentLength(body.length)
                .body(body);
            } else if (entity instanceof String) {
                String body = (String) entity;
                final byte[] entityBytes = body.getBytes(DEFAULT_READ_CHARSET);
                return HttpResponse.status(HttpStatus.valueOf(response.getStatus().getStatusCode()))
                    .contentType(response.getContentHeader())
                    .headers(headers)
                    .contentLength(entityBytes.length)
                    .body(entityBytes);
            } else {
                throw new IOException("Illegal entity object in ODataResponse of type '" + entity.getClass() + "'.");
            }
        } else {
            throw new IOException("response.getEntity() is null!");
        }
    }

    private byte[] handleStream(InputStream stream) throws IOException {
        byte[] buffer = getBuffer();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int len;
            while ((len = stream.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        } finally {
            stream.close();
        }
        return out.toByteArray();
    }

    private byte[] getBuffer() {
        int bufferSize = DEFAULT_BUFFER_SIZE;
        String bufSizeInit = getInitParameter(BUFFER_SIZE);
        if (bufSizeInit != null) {
            try {
                bufferSize = Integer.parseInt(bufSizeInit);
                if (bufferSize <= 0) {
                    bufferSize = DEFAULT_BUFFER_SIZE;
                }
            } catch (NumberFormatException ignored) {
                // this exception is ignored because if parameter is not parse able the default
                // is used
            }
        }

        return new byte[bufferSize];
    }

    private HttpResponse<?> createNotImplementedResponse(final ODataExceptionWrapper exceptionWrapper, final MessageReference messageReference) throws IOException {
        // RFC 2616, 5.1.1: "An origin server SHOULD return the status code [...]
        // 501 (Not Implemented) if the method is unrecognized [...] by the origin
        // server."
        ODataResponse response = exceptionWrapper
                .wrapInExceptionResponse(new ODataNotImplementedException(messageReference));
        return createResponse(response);
    }

    private HttpResponse<?> createMethodNotAllowedResponse(final ODataExceptionWrapper exceptionWrapper, final MessageReference messageReference) throws IOException {
        ODataResponse response = exceptionWrapper
                .wrapInExceptionResponse(new ODataMethodNotAllowedException(messageReference));
        return createResponse(response);
    }

    private HttpResponse<?> createNotAcceptableResponse(final ODataExceptionWrapper exceptionWrapper, final MessageReference messageReference) throws IOException {
        ODataResponse response = exceptionWrapper
                .wrapInExceptionResponse(new ODataNotAcceptableException(messageReference));
        return createResponse(response);
    }

    private HttpResponse<?> createServiceUnavailableResponse(final ODataExceptionWrapper exceptionWrapper, MessageReference messageReference) throws IOException {
        ODataResponse response = exceptionWrapper
                .wrapInExceptionResponse(new ODataInternalServerErrorException(messageReference));
        return createResponse(response);
    }

    private ODataExceptionWrapper getODataExceptionWrapper(final ODataContext context, final HttpRequest<?> request) {
        @SuppressWarnings({ "unchecked", "rawtypes" })
        final Map<String, String> queryParameters = new HashMap(request.getParameters().asProperties());
        final List<String> acceptHeaderContentTypes = request.getHeaders().accept().stream().map(MediaType::getName).collect(Collectors.toList()); 
        return new ODataExceptionWrapper(context, queryParameters, acceptHeaderContentTypes);
    }

}