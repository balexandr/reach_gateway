module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class ReachGateway < Gateway
      # Company changed their name from GoInterpay -> Reach but haven't updated
      # their endpoints at this time. Old URLs still worked.
      self.test_url = 'https://checkout-sandbox.gointerpay.net/v2.18/'
      self.live_url = 'https://checkout.gointerpay.net/v2.18/'

      #
      # Order ID = Reach Order Number
      #
      def initialize(options = {})
        requires!(options, :merchant_id, :secret, :test)
        super
      end

      # Creates a merchant's order within Reach without billing information.
      def create(options = {})
        post = {}

        add_transaction_parameters(post, nil, options)
        add_items(post, options)
        add_shipping(post, options)
        add_additional_charges(post, options)
        add_consumer(post, options)
        add_discounts(post, options)

        commit('create', post)
      end

      # Authorize payment for an order. This requires that the specified order has
      # been created but not authorized yet.
      # Since this call may contain cardholder data it must be made directly from
      # the shopper’s browser unless the Merchant is PCI DSS Level 1 compliant.
      def authorize(credit_card_or_contract_id, options = {})
        if options[:order_id].blank?
          order_id = create_order_id(options)
          options[:order_id] = order_id if order_id.present?
        end

        post = {} if post.blank?
        add_transaction_parameters(post, credit_card_or_contract_id, options)

        card = {}
        if !credit_card_or_contract_id.nil? && !credit_card_or_contract_id.is_a?(String)
          add_card(card, credit_card_or_contract_id)
        end

        commit('authorize', post, card)
      end

      # Reach does an auth/capture if the options[:capture] field
      # is set to true.
      def purchase(credit_card_or_contract_id, options = {})
        authorize(credit_card_or_contract_id, options)
      end

      # Creates a contract within Reach. Since this call may contain cardholder data
      # it must be made directly from the shopper’s browser  unless the Merchant is PCI DSS
      # Level 1 compliant. Unless otherwise specified, the requirements of each field is the
      # same as specified in checkout above.
      def store(credit_card_or_contract_id, options = {})
        post = {}

        add_transaction_parameters(post, credit_card_or_contract_id, options)
        add_consumer(post, options)

        card = {}
        add_card(card, credit_card_or_contract_id) unless credit_card_or_contract_id.is_a?(String)

        commit('openContract', post, card)
      end

      # Cancel a pre-authorized order. This requires that payment has not been captured.
      #
      # This request should not be called directly from the shopper's browser.
      def void(options = {})
        post = {}

        set_order_id(options)
        add_transaction_parameters(post, nil, options)

        commit('cancel', post)
      end

      # Submit a full or partial refund for an order that has been captured.
      #
      # This request should not be called directly from the shopper’s browser.
      def refund(money, options = {})
        post = {}

        options[:order_id] = retrieve_order_id(options[:reference_id]) if options[:order_id].blank?
        options[:amount] = money
        add_transaction_parameters(post, nil, options)

        commit('refund', post)
      end

      # Capture a pre-authorized order. This requires that the payment method support
      # pre-authorization and the Capture flag to be false in the related checkout or
      # authorize request.
      #
      # This request should not be called directly from the shopper’s browser.
      def capture(options = {})
        post = {}

        set_order_id(options)
        add_transaction_parameters(post, nil, options)

        commit('capture', post)
      end

      # Query order information from the Reach system. If the order is not found,
      # an HTTP 404 response will be returned. If there is a system problem with
      # querying the order, an HTTP 503 response will be returned and the request
      # should be tried again.
      #
      # This request should never be called directly from the shopper’s browser.
      def query(options = {})
        post = {}
        add_transaction_parameters(post, nil, options)

        commit('query', post)
      end

      private

      def set_order_id(options)
        if options[:order_id].blank?
          reference_id = options.delete(:reference_id)
          options[:order_id] = retrieve_order_id(reference_id)
        end
      end

      def create_order_id(options = {})
        new_order = create(options)
        new_order.params['OrderId']
      end

      # Retrieve an existing order's ID
      def retrieve_order_id(reference_id)
        return false if reference_id.blank?

        existing_orders = query({reference_id: reference_id}).params

        if existing_orders['Orders'].present?
          existing_orders = existing_orders['Orders'].sort_by { |order| order['Times']['Created'] }.reverse
          order_id = existing_orders.first['OrderId']
        end

        order_id
      end

      def add_transaction_parameters(post, credit_card_or_contract_id, options = {})
        post[:MerchantId] = @options[:merchant_id]
        post[:ReferenceId] = options[:reference_id]
        post[:ConsumerCurrency] = options[:consumer_currency]
        post[:OrderId] = options[:order_id]
        post[:Capture] = options[:capture]
        post[:PaymentMethod] = options[:payment_method]
        post[:IssuerId] = options[:issuer_id]
        post[:ConsumerIpAddress] = options[:ip_address]
        post[:Return] = options[:return_url]
        post[:ViaAgent] = options[:via_agent]
        post[:OpenContract] = options[:open_contract]
        post[:ContractId] = credit_card_or_contract_id if credit_card_or_contract_id.is_a?(String)
        post[:Amount] = options[:amount]
        post[:AcceptLiability] = options[:accept_liability] || false
        post[:DeviceFingerprint] = options[:device_fingerprint]
        post[:Notify] = options[:notify]
        post[:RateOfferId] = options[:rate_offer_id]
        post.reject! { |k, v| v.nil? }
      end

      # Add credit card to hash
      # return if ContractId is present
      def add_card(card, tender)
        card[:Name] = tender.first_name + ' ' + tender.last_name
        card[:Number] = tender.number
        card[:VerificationCode] = tender.verification_value
        card[:Expiry] = {}
        card[:Expiry][:Month] = tender.month
        card[:Expiry][:Year] = tender.year
      end

      # Add order items to an array with overall total
      def add_items(post, options)
        post[:Items] = []
        items = options[:items]

        return if items.blank?

        items.each do |item|
          item_hash = {}

          item_hash[:Description] = item[:description]
          item_hash[:ConsumerPrice] = item[:price]
          item_hash[:Quantity] = item[:quantity]
          item_hash[:Sku] = item[:sku]

          post[:Items] << item_hash
        end

        post[:ConsumerTotal] = options[:order_total]
      end

      # Add order shipping info
      def add_shipping(post, options)
        shipping = options[:shipping]

        return post[:ShippingRequired] = false if shipping.blank?

        post[:Shipping] = {}

        post[:Shipping][:ConsumerPrice] = shipping[:price] || 0.00
        post[:Shipping][:ConsumerTaxes] = shipping[:tax] || 0.00
        post[:Shipping][:ConsumerDuty] = shipping[:duty] || 0.00

        address = options[:shipping_address]

        return post if address.blank?

        post[:Consignee] = {}

        post[:Consignee][:Name] = address[:name]
        post[:Consignee][:Company] = address[:company] if address[:company].present?
        post[:Consignee][:Phone] = address[:phone] if address[:phone].present?
        post[:Consignee][:Address] = address[:address1]
        post[:Consignee][:City] = address[:city]
        post[:Consignee][:Region] = address[:state]
        post[:Consignee][:PostalCode] = address[:zip]
        post[:Consignee][:Country] = address[:country]
      end

      # Additional charges associated with order
      def add_additional_charges(post, options)
        charges = options[:additional_charges]

        return if charges.blank?

        post[:Charges] = []

        charges.each do |charge|
          post[:Charges] << { Name: charge[:name], ConsumerPrice: charge[:price] }
        end
      end

      # Add discounts
      def add_discounts(post, options)
        discounts = options[:discounts]

        return if discounts.blank?

        post[:Discounts] = []

        discounts.each do |discount|
          post[:Discounts] << { Name: discount[:name], ConsumerPrice: discount[:price] }
        end
      end

      # Add customer details based off billing or shipping address
      def add_consumer(post, options)
        address = options[:billing_address]

        return if address.blank?

        post[:Consumer] = {}

        post[:Consumer][:Name] = address[:name]
        post[:Consumer][:Email] = address[:email]
        post[:Consumer][:Company] = address[:company] if address[:company].present?
        post[:Consumer][:Phone] = address[:phone] if address[:phone].present?
        post[:Consumer][:Address] = address[:address1]
        post[:Consumer][:City] = address[:city]
        post[:Consumer][:Region] = address[:state]
        post[:Consumer][:PostalCode] = address[:zip]
        post[:Consumer][:Country] = address[:country]
      end

      def commit(action, parameters, card = {})
        url = (test? ? test_url : live_url) + action

        begin
          response = parse(ssl_post(url, format_data(card, parameters)))
          validated = validate_response(response)
        rescue ResponseError => e
          response = {'Error' => {'Code' => e.response.body }}
          validated = false
        end

        signature = response[:signature]
        response = parse_json(response)
        response.merge!(Signature: signature)

        Response.new(
          success_from(action, response, validated),
          message_from(response, validated),
          response,
          test: test?
        )
      end

      def validate_response(response)
        response_signature = response[:signature]
        confirm_signature = add_signature(response[:response] || '')

        if response_signature == confirm_signature
          true
        else
          false
        end
      end

      def add_signature(request)
        secret = @options[:secret].encode('utf-8')
        json = request.encode('utf-8')
        Base64.strict_encode64(OpenSSL::HMAC.digest('sha256', secret, json))
      end

      def format_data(card, parameters = {})
        post = {}
        post[:request] = parameters.to_json
        post[:signature] = add_signature(parameters.to_json)
        post[:card] = card.to_json if card.present?
        post.collect { |key, value| "#{key}=#{CGI.escape(value.to_s)}" }.join("&")
      end

      def success_from(action, response, validated)
        if response.dig('Error','Code') || !validated
          false
        else
          true
        end
      end

      def message_from(response, validated)
        response.dig('Error','Code') || 'success'
      end

      def parse_json(response)
        JSON.parse(response[:response])
      rescue
        response
      end

      def parse(body)
        response_fields = Hash[CGI::parse(body).map{|k,v| [k.downcase,v.first]}]

        parsed = {}
        parsed[:response] = response_fields['response']
        parsed[:signature] = response_fields['signature']

        parsed
      end
    end
  end
end
