package com.keycloakintegration.keycloak.service;

import com.keycloakintegration.keycloak.dto.*;
import com.keycloakintegration.keycloak.exception.CustomerException;
import com.keycloakintegration.keycloak.utils.Constants;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.*;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.keycloak.representations.idm.authorization.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Service
public class KeycloakService {


    private final RealmResource realmResource;
    private final Keycloak keycloak;
    private final String keycloakUrl;
    private final String keycloakClientId;
    private final String keycloakClientSecret;
    private final String keycloakUsername;
    private final String keycloakPassword;
    private final String keycloakRealm;
    private final RestClient restClient;
    private final String introspectUrl;
    private final String rptUrl;

    public KeycloakService(WebClient.Builder webClientBuilder,
                           @Value("${keycloak.url}") String keycloakUrl,
                           @Value("${keycloak.client-id}") String keycloakClientId,
                           @Value("${keycloak.client-secret}") String keycloakClientSecret,
                           @Value("${keycloak.username}") String keycloakUsername,
                           @Value("${keycloak.password}") String keycloakPassword,
                           @Value("${keycloak.realm}") String keycloakRealm,
                           RestClient.Builder restClientBuilder,
                           @Value("${keycloak.introspect.url}") String introspectUrl,
                           @Value("${keycloak.rpt.url}") String rptUrl) {
        this.keycloakUrl = keycloakUrl;
        this.keycloakClientId = keycloakClientId;
        this.keycloakClientSecret = keycloakClientSecret;
        this.keycloakUsername = keycloakUsername;
        this.keycloakPassword = keycloakPassword;
        this.keycloakRealm = keycloakRealm;
        this.introspectUrl = introspectUrl;
        this.rptUrl = rptUrl;
        keycloak = KeycloakBuilder
                .builder()
                .clientId(keycloakClientId)
                .clientSecret(keycloakClientSecret)
                .grantType(OAuth2Constants.PASSWORD)
                .realm(keycloakRealm)
                .username(keycloakUsername)
                .password(keycloakPassword)
                .serverUrl(keycloakUrl)
                .build();
        realmResource = keycloak.realm(keycloakRealm);
        this.restClient = restClientBuilder
                .baseUrl(keycloakUrl)
                .build();
    }

    public APIResponse createUser(UserRequest userRequest) {
        try {
            UserRepresentation userRepresentation = userExistsByName(userRequest.getUserName());
            if (null == userRepresentation) {
                userRepresentation = registerUser(userRequest);
                assignRoleToUser(userRepresentation.getId(), userRequest.getRole());
            }
            manageUserAccessPermissions(userRequest.getAccessInfos(),
                    userRepresentation.getUsername(),
                    userRepresentation.getId());
            return getApiResponse(userRepresentation.getId());
        } catch (CustomerException e) {
            log.error("Exception Occurred - {}", e.getMessage());
            throw new CustomerException(e.getStatusCode(),
                    e.getReason());
        } catch (Exception e) {
            log.error("Exception Occurred - {}", e.getMessage(), e);
            throw new CustomerException(HttpStatusCode.valueOf(500),
                    "Something went wrong");
        }
    }


    /**
     * Fetches user information by userId.
     *
     * @param userId the ID of the user whose information is to be fetched
     * @return the UserResponse containing the user's information
     */
    public UserResponse getUserInfoByUserId(String userId) {
        UserRepresentation userRepresentation = fetchUserById(userId);
        List<UserPermissionResponse> userPermissionResponses = fetchUserAccessInfo(userRepresentation.getId());
        return UserResponse
                .builder()
                .userPermissionResponses(userPermissionResponses)
                .userName(userRepresentation.getUsername())
                .firstName(userRepresentation.getFirstName())
                .lastName(userRepresentation.getLastName())
                .userId(userRepresentation.getId())
                .build();
    }




    /**
     * Builds the API response to return.
     *
     * @param userId the ID of the user to be included in the response
     * @return the API response
     */
    private APIResponse getApiResponse(String userId) {
        return APIResponse
                .builder()
                .message("User Created with id - " + userId)
                .status(HttpStatus.CREATED.value())
                .build();
    }

    /**
     * Registers a user in the Keycloak server.
     *
     * @param userRequest the request to create a user
     * @return the response for the created user
     */
    private UserRepresentation registerUser(UserRequest userRequest) {
        Response response;
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setFirstName(userRequest.getFirstName());
        userRepresentation.setLastName(userRequest.getLastName());
        userRepresentation.setUsername(userRequest.getUserName());
        userRepresentation.setEmail(userRequest.getEmail());
        userRepresentation.setCredentials(credentialRepresentation(userRequest.getPassword()));
        userRepresentation.setEnabled(true);
        userRepresentation.setEmailVerified(true);
        response = realmResource.users().create(userRepresentation);
        handleFailureCases(response);
        userRepresentation = realmResource
                .users()
                .search(userRequest.getUserName())
                .get(0);
        return userRepresentation;
    }

    /**
     * Manages user access permissions by creating or updating resources,
     * creating policies, and creating permissions for the given user.
     *
     * @param accessInfos a list of user access information objects
     * @param userName the username of the user
     * @param userId the ID of the user
     */
    private void manageUserAccessPermissions(List<UserAccessInfo> accessInfos,
                                             String userName,
                                             String userId) {
        if (null == accessInfos || accessInfos.isEmpty()) {
            return;
        }
        ClientResource clientResource = getClientResource();
        Set<String> resourceNames = new HashSet<>();
        AtomicReference<String> policyName = new AtomicReference<>();
        accessInfos
                .forEach(userAccessInfo -> {
                    String resourceName = createOrUpdateResources(userAccessInfo, clientResource);
                    resourceNames.add(resourceName);
                    policyName.set(createPolicy(userName, userId));
                });
        createPermission(clientResource, resourceNames, policyName.get(), userName);
    }

    /**
     * Creates a new policy if it does not already exist for the given userName.
     *
     * @param userName the username for which the policy should be created
     * @param userId the userId associated with the policy
     * @return the name of the created policy
     */
    private String createPolicy(String userName,
                                String userId) {
        PolicyRepresentation policyRepresentation = getPolicyRepresentationByUserId(userName);
        if (policyRepresentation == null) {
            policyRepresentation = new PolicyRepresentation();
            policyRepresentation.setName(userName);
            policyRepresentation.setDescription(String.format("User policy for userId=%s", userId));
            policyRepresentation.setType("user");
            policyRepresentation.setLogic(Logic.POSITIVE);
            policyRepresentation.setConfig(getConfig(userName, userId));
            Response response = getClientResource().authorization().policies().create(policyRepresentation);
            policyRepresentation = response.readEntity(PolicyRepresentation.class);
            response.close();
        }
        log.info("Policy created");
        return policyRepresentation.getName();
    }

    /**
     * Constructs a configuration map for a policy with the specified policyName and userId.
     *
     * @param policyName the name of the policy to configure
     * @param userId the ID of the user associated with the policy
     * @return a Map containing the configuration details
     */
    private Map<String, String> getConfig(String policyName,
                                          String userId) {
        Map<String, String> config = new HashMap<>();
        config.put("users", "[\"" + userId + "\"]");
        return config;
    }

    /**
     * Retrieves a PolicyRepresentation object by the username.
     *
     * @param userName the username associated with the policy to retrieve
     * @return the PolicyRepresentation object if found, null if not found
     */
    private PolicyRepresentation getPolicyRepresentationByUserId(String userName) {
        ClientResource clientResource = getClientResource();
        return clientResource
                .authorization()
                .policies()
                .findByName(userName);
    }


    /**
     * Retrieves an AuthzClient instance configured with the specified parameters.
     *
     * @return the configured AuthzClient instance
     */
    private AuthzClient getAuthzClient() {
        Map<String, Object> secret = new HashMap<>();
        secret.put("secret", keycloakClientSecret);
        Configuration configuration = new Configuration(
                keycloakUrl,
                keycloakRealm,
                keycloakClientId,
                secret,
                null
        );
        return AuthzClient.create(configuration);
    }

    /**
     * Creates or updates a resource based on the provided UserAccessInfo.
     * If a resource with the module name does not exist, it creates a new resource.
     * If a resource with the module name already exists, it updates the existing resource.
     *
     * @param userAccessInfo the UserAccessInfo containing module information
     * @param clientResource the ClientResource for the client
     * @return the name of the created or updated resource
     */
    private String createOrUpdateResources(UserAccessInfo userAccessInfo,
                                           ClientResource clientResource) {
        ResourceRepresentation resourceRepresentation = findResourceByName(userAccessInfo.getModuleName());
        ResourceRepresentation representation = getResourceRepresentation(userAccessInfo);
        if (null == resourceRepresentation) {
            Response response = clientResource
                    .authorization()
                    .resources()
                    .create(representation);
            handleFailureCases(response);
            representation = response.readEntity(ResourceRepresentation.class);
        } else {
            representation.setId(resourceRepresentation.getId());
            clientResource
                    .authorization()
                    .resources()
                    .resource(resourceRepresentation.getId())
                    .update(resourceRepresentation);
        }
        log.info("Resource Created ");
        return representation.getName();
    }

    private String createOrUpdatePolicy(String userName) {
        return null;
    }

    /**
     * Builds a new ResourceRepresentation object based on the provided UserAccessInfo.
     *
     * @param userAccessInfo the UserAccessInfo request to build a ResourceRepresentation object
     * @return the constructed ResourceRepresentation object
     */
    private ResourceRepresentation getResourceRepresentation(UserAccessInfo userAccessInfo) {
        ResourceRepresentation resourceRepresentation = new ResourceRepresentation();
        resourceRepresentation
                .setName(userAccessInfo.getModuleName());
        resourceRepresentation
                .setUris(userAccessInfo.getUrls());
        return resourceRepresentation;
    }

    /**
     * Finds a resource by its name.
     *
     * @param name the name of the resource to find
     * @return the ResourceRepresentation if found, null if not found
     * @throws CustomerException if more than one resource exists with the given name
     */
    private ResourceRepresentation findResourceByName(String name) {
        ClientResource clientResource = getClientResource();
        final List<ResourceRepresentation> resourcesRepresentations = clientResource
                .authorization()
                .resources()
                .findByName(name);
        if (resourcesRepresentations.size() > 1) {
            throw new CustomerException(HttpStatus.CONFLICT, "More than one resources exists with the given name");
        }
        return resourcesRepresentations.isEmpty() ? null : resourcesRepresentations.get(0);
    }

    /**
     * Retrieves the ClientResource for the client with the specified client ID ("Testing").
     * If no client is found, it throws a CustomerException with a NOT_FOUND status.
     *
     * @return the ClientResource for the specified client
     * @throws CustomerException if no client is found with the specified client ID
     */

    private ClientResource getClientResource() {
        final List<ClientRepresentation> clientRepresentations = realmResource
                .clients()
                .findByClientId(keycloakClientId);
        if (clientRepresentations.isEmpty()) {
            throw new CustomerException(HttpStatus.NOT_FOUND, "Clients are not found with name");
        }
        String clientId = clientRepresentations
                .get(0)
                .getId();
        log.info("clientId - {}", clientId);
        return realmResource
                .clients()
                .get(clientId);
    }

    /**
     * Retrieves the ID of the Keycloak client associated with the current realm by its client ID.
     *
     * @return the ID of the Keycloak client
     * @throws CustomerException if no client is found with the specified client ID
     */
    private String getKeycloakClientId() {
        final List<ClientRepresentation> clientRepresentations = realmResource
                .clients()
                .findByClientId(keycloakClientId);
        if (clientRepresentations.isEmpty()) {
            throw new CustomerException(HttpStatus.NOT_FOUND, "Clients are not found with name");
        }
        return clientRepresentations
                .get(0)
                .getId();
    }

    /**
     * Creates or updates a permission for the specified resources and policy.
     * If a permission with the given permissionName exists, it updates the existing permission.
     * Otherwise, it creates a new permission.
     *
     * @param clientResource the ClientResource used to interact with Keycloak
     * @param resourceIds the IDs of the resources to associate with the permission
     * @param policyId the ID of the policy to associate with the permission
     * @param permissionName the name of the permission to create or update
     */
    private void createPermission(ClientResource clientResource,
                                  Set<String> resourceIds,
                                  String policyId,
                                  String permissionName) {
        ResourcePermissionRepresentation resourcePermissionRepresentation =
                getPermissionByName(clientResource, permissionName);
        ResourcePermissionRepresentation representation = new ResourcePermissionRepresentation();
        representation.setName(permissionName + "-permission");
        representation.setLogic(Logic.POSITIVE);
        representation.setPolicies(Collections.singleton(policyId));
        representation.setResources(resourceIds);
        representation.setType("resource");
        if (null != resourcePermissionRepresentation) {
            clientResource
                    .authorization()
                    .permissions()
                    .resource()
                    .findById(resourcePermissionRepresentation.getId())
                    .update(representation);
            log.info("Permission Updated");
        } else {
            final Response response = clientResource
                    .authorization()
                    .permissions()
                    .resource()
                    .create(representation);
            handleFailureCases(response);
            log.info("Permission Created");
        }
    }

    /**
     * Retrieves a ResourcePermissionRepresentation by permission name.
     * This method sends a REST request to the specified URI to fetch the permission.
     *
     * @param clientResource the ClientResource for the client
     * @param permissionName the name of the permission to be retrieved
     * @return the ResourcePermissionRepresentation if found, null otherwise
     */
    private ResourcePermissionRepresentation getPermissionByName(ClientResource clientResource,
                                                                 String permissionName) {
        String clientId = getKeycloakClientId();
        String uri = UriComponentsBuilder
                .fromUriString("/admin/realms/{realm}/clients/{clientId}/authz/resource-server/permission")
                .queryParam("name", permissionName)
                .buildAndExpand(keycloakRealm, clientId)
                .toUriString();

        String token = generateAccessTokenByUserNameAndPassword(keycloakUsername, keycloakPassword);

        RestClient restClient = RestClient.builder().build();

        ResponseEntity<ResourcePermissionRepresentation[]> response = restClient
                .get()
                .uri(uri)
                .header(HttpHeaders.AUTHORIZATION, Constants.BEARER + token)
                .retrieve()
                .toEntity(ResourcePermissionRepresentation[].class);

        ResourcePermissionRepresentation[] permissionRepresentations = response.getBody();

        if (permissionRepresentations == null || permissionRepresentations.length == 0) {
            return null;
        }
        return permissionRepresentations[0];
    }

    /**
     * Generates an access token using the specified username and password.
     *
     * @param userName the username to authenticate with
     * @param password the password to authenticate with
     * @return the generated access token
     */
    private String generateAccessTokenByUserNameAndPassword(String userName,
                                                            String password) {
        AuthzClient authzClient = getAuthzClient();
        AccessTokenResponse tokenResponse = authzClient.obtainAccessToken(userName, password);
        return tokenResponse.getToken();
    }


    /**
     * Assigns a role to the user identified by userId.
     *
     * @param userId the ID of the user to assign the role
     * @param role the role to be assigned to the user
     */
    private void assignRoleToUser(String userId,
                                  String role) {
        RoleRepresentation roleRepresentation = realmResource
                .roles()
                .get(role)
                .toRepresentation();
        UserResource userResource = realmResource
                .users()
                .get(userId);
        List<CredentialRepresentation> representation1 = userResource.credentials();
        realmResource
                .users()
                .get(userId)
                .roles()
                .realmLevel()
                .add(Collections.singletonList(roleRepresentation));
    }

    /**
     * It searches users based on the username
     * Return 0 index value
     *
     * @param userName - the userName to be search
     * @return - the UserRepresentation after search the users by username
     */
    private UserRepresentation getUserInfo(String userName) {
        return realmResource
                .users()
                .search(userName)
                .get(0);
    }

    /**
     * Constructs a list containing a CredentialRepresentation object initialized with the provided password.
     *
     * @param password the password value to set in the CredentialRepresentation
     * @return a list containing the CredentialRepresentation object
     */
    private List<CredentialRepresentation> credentialRepresentation(String password) {
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setValue(password);
        credentialRepresentation.setTemporary(false);
        return List.of(credentialRepresentation);
    }

    /**
     * Handles failure cases based on the response status.
     * If the response status is not CREATED (HTTP status code 201),
     * it reads the error message from the response and throws a CustomerException.
     *
     * @param response the Response object received from the HTTP request
     */
    private void handleFailureCases(Response response) {
        Response.StatusType statusInfo = response.getStatusInfo();
        ErrorRepresentation message;
        if (statusInfo.getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            message = response.readEntity(ErrorRepresentation.class);
            response.close();
            throw new CustomerException(HttpStatusCode.valueOf(response.getStatus()),
                    message.getErrorMessage());
        }
    }

    /**
     * Checks if a user exists by username.
     * If a user with the given name exists, it returns the first matching UserRepresentation.
     * If no user with the given name exists, it returns null.
     *
     * @param name the username to be searched
     * @return the UserRepresentation of the first matching user if one exists, null otherwise
     */
    private UserRepresentation userExistsByName(String name) {
        List<UserRepresentation> userRepresentations = realmResource
                .users()
                .search(name);
        if (userRepresentations.isEmpty()) {
            return null;
        }
        return userRepresentations.get(0);
    }

    /**
     * Fetches a user by userId.
     *
     * @param userId the ID of the user to fetch
     * @return the UserRepresentation of the fetched user
     */
    private UserRepresentation fetchUserById(String userId) {
        final UserResource userResource = realmResource
                .users()
                .get(userId);
        if (null == userResource) {
            throw new CustomerException(HttpStatus.NO_CONTENT, "User Not Found");
        }
        return userResource.toRepresentation();
    }

    /**
     * Fetches user access information based on the userId.
     *
     * @param userId the ID of the user for whom to fetch access information
     * @return a list of UserPermissionResponse objects representing the user's permissions
     */
    private List<UserPermissionResponse> fetchUserAccessInfo(String userId) {
        String accessToken = getUserAccessToken(userId);
        String rptToken = getRptToken(accessToken);
        if (null == rptToken) {
            return new ArrayList<>();
        }
        return introspectRptToken(rptToken);
    }


    //TODO - Need to replace this logic

    /**
     * Obtains an access token for a user.
     *
     * @param userId the ID of the user to obtain the access token for
     * @return the access token as a String
     */
    private String getUserAccessToken(String userId) {
        AuthzClient authzClient = getAuthzClient();
        //TODO - values are hardcoded should be dynamic
        final AccessTokenResponse accessTokenResponse = authzClient
                .obtainAccessToken("test2", "123");
        return accessTokenResponse.getToken();
    }

    /**
     * Retrieves an RPT token using the provided access token.
     *
     * @param accessToken the access token used to obtain the RPT token
     * @return the RPT token string, or null if unsuccessful
     */
    private String getRptToken(String accessToken) {
        String uri = UriComponentsBuilder
                .fromUriString(rptUrl)
                .buildAndExpand(keycloakRealm)
                .toUriString();
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        formData.add("audience", keycloakClientId);
        final ResponseEntity<AccessTokenResponse> responseEntity = restClient
                .post()
                .uri(uri)
                .header(HttpHeaders.CONTENT_TYPE, Constants.APPLICATION_X_WWW_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, Constants.BEARER + accessToken)
                .body(formData)
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, (request, response) -> {
                    if (response.getStatusCode().isSameCodeAs(HttpStatusCode.valueOf(HttpStatus.FORBIDDEN.value()))) {
                        log.info("No Permission for this");
                    } else if (response.getStatusCode().is4xxClientError()) {
                        throw new CustomerException(HttpStatus.BAD_REQUEST, "Client error occurred while getting RPT token");
                    } else if (response.getStatusCode().is5xxServerError()) {
                        throw new CustomerException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Server error occurred while getting RPT token");
                    }
                })
                .toEntity(AccessTokenResponse.class);
        if (responseEntity.getStatusCode().is2xxSuccessful() && null != responseEntity.getBody()) {
            return responseEntity.getBody().getToken();
        }
        return null;
    }

    /**
     * Introspects an RPT token to retrieve user permissions.
     *
     * @param rptToken the RPT token to introspect
     * @return a list of UserPermissionResponse objects representing user permissions
     */
    private List<UserPermissionResponse> introspectRptToken(String rptToken) {
        String uri = UriComponentsBuilder
                .fromUriString(introspectUrl)
                .buildAndExpand(keycloakRealm)
                .toUriString();
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add(Constants.TOKEN_TYPE_HINT, Constants.REQUESTING_PARTY_TOKEN);
        formData.add(Constants.TOKEN, rptToken);
        final ResponseEntity<PermissionsResponse> responseEntity = restClient
                .post()
                .uri(uri)
                .headers(httpHeaders -> httpHeaders.setBasicAuth(keycloakClientId, keycloakClientSecret))
                .body(formData)
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, (request, response) -> {
                    if (response.getStatusCode().is4xxClientError()) {
                        throw new CustomerException(HttpStatus.BAD_REQUEST, "Client error occurred while getting RPT token");
                    } else if (response.getStatusCode().is5xxServerError()) {
                        throw new CustomerException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Server error occurred while getting RPT token");
                    }
                })
                .toEntity(PermissionsResponse.class);
        if (responseEntity.getStatusCode().is2xxSuccessful() && null != responseEntity.getBody()) {
            return responseEntity.getBody().getPermissions();
        }
        return new ArrayList<>();
    }
}
