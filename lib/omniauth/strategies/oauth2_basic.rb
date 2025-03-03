# frozen_string_literal: true

class OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  uid do
    if path = SiteSetting.oauth2_callback_user_id_path.split(".")
      recurse(access_token, [*path]) if path.present?
    end
  end

  info do
    if paths = SiteSetting.oauth2_callback_user_info_paths.split("|")
      result = Hash.new
      paths.each do |p|
        segments = p.split(":")
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split(".")]
          result[key] = recurse(access_token, path)
        end
      end
      result
    end
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil unless obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end

  # --- PKCE Support Added ---
  #
  # Override request_phase to generate a PKCE code_verifier and code_challenge.
  # The code_verifier is stored in the session for later use during token exchange.
  # The code_challenge and method are added to the authorize URL.
  def request_phase
    # Generate a random code_verifier
    code_verifier = SecureRandom.urlsafe_base64(64)
    
    # Compute the code_challenge using SHA256 and Base64 URL-safe encoding (remove trailing '=')
    code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier)).delete("=")

    # Store the code_verifier in the session (for later token exchange)
    session["oauth2_code_verifier"] = code_verifier

    # Ensure authorize_params is a hash and add PKCE parameters
    options.authorize_params ||= {}
    options.authorize_params[:code_challenge] = code_challenge
    options.authorize_params[:code_challenge_method] = "S256"

    super
  end

  # --- Fix for Missing Code Verifier in Token Request ---
  # This ensures that the code_verifier is sent when exchanging the authorization code for a token.
  def token_params
    super.tap do |params|
      params[:code_verifier] = session["oauth2_code_verifier"]
    end
  end
end
