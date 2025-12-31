import base64
import datetime
import hashlib
import hmac
import json
import logging
import math

import razorpay


import requests
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db import transaction
from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Q , Case, When, IntegerField, Value
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.template.loader import get_template
from google.auth import jwt
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import get_object_or_404
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView

from django.utils.html import strip_tags

from django.utils.encoding import force_str

from backend.models import User, Otp, PasswordResetToken, Token, Category, Slide, PageItem, Product, ProductOption, \
    OrderedProduct, Order, ContactInfo, ProductImage, InformMe, AppVersion
from backend.serializers import UserSerializer, CategorySerializer, SlideSerializer, PageItemSerializer, \
    ProductSerializer, WishlistSerializer, CartSerializer, AddressSerializer, ItemOrderSerializer, \
    OrderDetailsSerializer, NotificationSerializer, OrderItemSerializer, ProductOptionSerializer, InformMeSerializer, \
    VersionCheckRequestSerializer
from backend.utils import send_otp, token_response, send_password_reset_email, IsAuthenticatedUser, cfSignature, \
    send_user_notification
from core import settings
from core.settings import TEMPLATES_BASE_URL, CF_ID, CF_KEY , RAZORPAY_KEY_ID, \
    RAZORPAY_KEY_SECRET
from rest_framework import status as http_status

from .serializers import PrivacyPolicySerializer

from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@csrf_exempt
def app_store_notifications(request):
    """
    Production endpoint to receive and process App Store Server Notifications.

    This view supports:
      - Legacy notifications that include a "notification_type" field.
      - Notifications with a signedPayload (App Store Server Notifications V2).

    If a signedPayload is present, the payload is verified using the Apple public key
    stored in settings.APPLE_PUBLIC_KEY and then processed.
    """
    # Allow only POST requests.
    if request.method != 'POST':
        logger.warning("Received non-POST request: %s", request.method)
        return JsonResponse({'error': 'Invalid request method. Only POST is supported.'}, status=405)

    try:
        # Decode the incoming JSON payload.
        payload = request.body.decode('utf-8')
        data = json.loads(payload)
        logger.info("Received raw notification data: %s", data)
    except Exception as e:
        logger.error("Error parsing JSON payload: %s", e)
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    # Check if the notification includes a signedPayload (for App Store Server Notifications V2).
    if 'signedPayload' in data:
        signed_payload = data['signedPayload']
        try:
            # Verify the JWT using Apple's public key and the ES256 algorithm.
            decoded_payload = jwt.decode(
                signed_payload,
                settings.APPLE_PUBLIC_KEY,
                algorithms=['ES256']
            )
            logger.info("Decoded signedPayload successfully: %s", decoded_payload)
            # Use the decoded payload for further processing.
            data = decoded_payload
        except jwt.ExpiredSignatureError:
            logger.error("Expired signature in signedPayload")
            return JsonResponse({'error': 'Expired signature'}, status=400)
        except jwt.InvalidTokenError as e:
            logger.error("Invalid token in signedPayload: %s", e)
            return JsonResponse({'error': 'Invalid token'}, status=400)
    else:
        logger.info("No signedPayload found; processing as legacy notification.")

    # Process the notification based on its type.
    notification_type = data.get("notification_type")
    if notification_type:
        if notification_type == "DID_RENEW":
            logger.info("Subscription renewed. Data: %s", data)
            # TODO: Add your renewal handling logic here.
        elif notification_type == "CANCEL":
            logger.info("Subscription cancelled. Data: %s", data)
            # TODO: Add your cancellation handling logic here.
        elif notification_type == "DID_FAIL_TO_RENEW":
            logger.info("Failed to renew subscription. Data: %s", data)
            # TODO: Add your failure handling logic here.
        else:
            logger.info("Unhandled notification type: %s", notification_type)
    else:
        logger.warning("Notification type not provided in data.")

    # Respond with a success status.
    return JsonResponse({'status': 'ok'}, status=200)


@api_view(['POST'])
def request_otp(request):
    email = request.data.get('email')
    phone = request.data.get('phone')

    if email and phone:
        if User.objects.filter(email=email).exists():
            return Response('email already exists', status=400)
        if User.objects.filter(phone=phone).exists():
            return Response('phone already exists', status=400)
        return send_otp(phone)
    else:
        return Response('data_missing', status=400)


@api_view(['POST'])
def resend_otp(request):
    phone = request.data.get('phone')
    if not phone:
        return Response('data_missing', 400)
    return send_otp(phone)


@api_view(['POST'])
def verify_otp(request):
    phone = request.data.get('phone')
    otp = request.data.get('otp')

    otp_obj = get_object_or_404(Otp, phone=phone, verified=False)

    if otp_obj.validity.replace(tzinfo=None) > datetime.datetime.utcnow():
        if otp_obj.otp == int(otp):
            otp_obj.verified = True
            otp_obj.save()
            return Response('otp_verified_successfully')
        else:
            return Response('Incorrect otp', 400)
    else:
        return Response('otp expired', 400)


@api_view(['POST'])
def create_account(request):
    email = request.data.get('email')
    phone = request.data.get('phone')
    password = request.data.get('password')
    fullname = request.data.get('fullname')
    fcmtoken = request.data.get('fcmtoken')

    if email and phone and password and fullname:
        otp_obj = get_object_or_404(Otp, phone=phone, verified=True)
        otp_obj.delete()

        user = User()
        user.email = email
        user.phone = phone
        user.fullname = fullname
        user.password = make_password(password)
        user.save()
        return token_response(user,fcmtoken)

    else:
        return Response('data_missing', 400)


@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    phone = request.data.get('phone')
    password = request.data.get('password')
    fcmtoken = request.data.get('fcmtoken')

    if email:
        user = get_object_or_404(User, email=email)
    elif phone:
        user = get_object_or_404(User, phone=phone)
    else:
        return Response('data_missing', 400)

    if check_password(password, user.password):
        return token_response(user,fcmtoken)
    else:
        return Response('incorrect password', 400)

@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def logout(request):
    # Grab the bearer token header
    token_header = request.headers.get('Authorization')

    # Parse logout_all query param: expect "true"/"false"
    logout_all_param = request.GET.get('logout_all', 'false').lower()
    logout_all = logout_all_param == 'true'

    if logout_all:
        # Delete *all* tokens for this user → logout everywhere
        Token.objects.filter(user=request.user).delete()
    else:
        # Delete only the current token → logout this device
        Token.objects.filter(token=token_header).delete()

    return Response({'message': 'logged_out'})
    return Response('logged_out')


@api_view(['POST'])
def password_reset_email(request):
    email = request.data.get('email')
    if not email:
        return Response('params_missing', 400)

    user = get_object_or_404(User, email=email)
    return send_password_reset_email(user)


@api_view(['GET'])
def password_reset_form(request, email, token):
    token_instance = PasswordResetToken.objects.filter(user__email=email, token=token).first()
    link_expired = get_template('pages/link-expired.html').render()
    if token_instance:
        if datetime.datetime.utcnow() < token_instance.validity.replace(tzinfo=None):
            return render(request, 'pages/new-password-form.html', {
                'email': email,
                'token': token,
                'base_url': TEMPLATES_BASE_URL
            })
        else:
            token_instance.delete()
            return HttpResponse(link_expired)
    else:
        return HttpResponse(link_expired)


@api_view(['POST'])
def password_reset_confirm(request):
    email = request.data.get('email')
    token = request.data.get('token')
    password1 = request.data.get('password1')
    password2 = request.data.get('password2')

    token_instance = PasswordResetToken.objects.filter(user__email=email, token=token).first()
    link_expired = get_template('pages/link-expired.html').render()

    if token_instance:
        if datetime.datetime.utcnow() < token_instance.validity.replace(tzinfo=None):
            if len(password1) < 8:
                return render(request, 'pages/new-password-form.html', {
                    'email': email,
                    'token': token,
                    'base_url': TEMPLATES_BASE_URL,
                    'error': 'Password length must be at least 8 characters!'
                })

            if password1 == password2:
                user = token_instance.user
                user.password = make_password(password1)
                user.save()
                token_instance.delete()
                Token.objects.filter(user=user).delete()
                return render(request, 'pages/password-updated.html')
            else:
                return render(request, 'pages/new-password-form.html', {
                    'email': email,
                    'token': token,
                    'base_url': TEMPLATES_BASE_URL,
                    'error': 'Password doesn\'t matched!'
                })
        else:
            token_instance.delete()
            return HttpResponse(link_expired)
    else:
        return HttpResponse(link_expired)


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def userdata(request):
    user = request.user
    data = UserSerializer(user, many=False).data
    return Response(data)


@api_view(['GET'])
def categories(request):
    list = Category.objects.all().order_by('position')
    data = CategorySerializer(list, many=True).data
    return Response(data)


@api_view(['GET'])
def slides(request):
    list = Slide.objects.all().order_by('position')
    data = SlideSerializer(list, many=True).data
    return Response(data)


@api_view(['GET'])
def pageitems(request):
    category = request.GET.get('category')

    pagination = LimitOffsetPagination()

    page_items = PageItem.objects.filter(category=category).order_by('position')

    queryset = pagination.paginate_queryset(page_items, request)

    data = PageItemSerializer(queryset, many=True).data

    return pagination.get_paginated_response(data)


@api_view(['GET'])
def viewall(request):
    page_item_id = request.GET.get('id')

    pagination = LimitOffsetPagination()

    product_options = get_object_or_404(PageItem,id=page_item_id).product_options.all()

    queryset = pagination.paginate_queryset(product_options, request)

    data = WishlistSerializer(queryset, many=True).data
    return pagination.get_paginated_response(data)


@api_view(['GET'])
def product_details(request):
    productId = request.GET.get('productId')
    product = get_object_or_404(Product, id=productId)
    data = ProductSerializer(product, many=False).data
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def update_wishlist(request):
    id = request.GET.get('id')
    action = request.GET.get('action')
    user = request.user

    if action == 'ADD':
        user.wishlist.add(id)
        user.save()
    elif action == 'REMOVE':
        user.wishlist.remove(id)
        user.save()
    return Response('updated')


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def update_cart(request):
    id = request.GET.get('id')
    action = request.GET.get('action')
    user = request.user

    if action == 'ADD':
        user.cart.add(id)
        user.save()
    elif action == 'REMOVE':
        user.cart.remove(id)
        user.save()
    return Response('updated')


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def wishlist(request):
    _wishlist = request.user.wishlist.all()
    data = WishlistSerializer(_wishlist, many=True).data
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def cart(request):
    id = request.GET.get('id')
    if id:
        products = ProductOption.objects.filter(id=id)
        data = CartSerializer(products, many=True).data
    else:
        # load all cart items
        products = request.user.cart.all()
        data = CartSerializer(products, many=True).data
    return Response(data)


@api_view(['POST'])
@permission_classes([IsAuthenticatedUser])
def updateaddress(request):
    name = request.data.get('name')
    address = request.data.get('address')
    pincode = request.data.get('pincode')
    contact_no = request.data.get('contact_no')

    if name and address and pincode and contact_no:
        try:
            user = request.user
            user.name = name
            user.address = address
            user.contact_no = contact_no
            user.pincode = pincode

            # Auto-fetch district and state from pincode using free API
            url = f"https://api.postalpincode.in/pincode/{pincode}"
            try:
                response = requests.get(url, timeout=5)
                data = response.json()

                if data and data[0]['Status'] == "Success":
                    post_office = data[0]['PostOffice'][0]
                    user.district = post_office.get('District', 'Not Available')
                    user.state = post_office.get('State', 'Not Available')
                else:
                    user.district = "Seoni"
                    user.state = "Madhya Pradesh"
            except Exception as api_err:
                user.district = "Seoni"
                user.state = "Madhya Pradesh"

            user.save()
            return Response(AddressSerializer(user).data)

        except Exception as e:
            return Response({'error': 'Failed to update address', 'details': str(e)}, status=400)
    else:
        return Response({'error': 'Missing required fields'}, status=400)

@api_view(['POST'])
@permission_classes([IsAuthenticatedUser])
def initiate_payment(request):
    items = request.data.get('items')
    from_cart = request.data.get('from_cart')
    tx_amount = request.data.get('tx_amount')
    payment_mode = request.data.get('payment_mode')

    query = Q(id=items[0]['id'])
    for item in items:
        query = query | Q(id=item['id'])

    product_options = ProductOption.objects.filter(query)

    ordered_products = []
    server_tx_amount = 0
    for option in product_options:
        for item in items:
            if str(option.id) == item['id']:
                option.quantity = option.quantity - item['quantity']
                order_tx_price = (option.product.offer_price * item['quantity']) + option.product.delivery_charge
                server_tx_amount = server_tx_amount + order_tx_price

                order_option = OrderedProduct()
                order_option.quantity = item['quantity']
                order_option.product_option = option
                order_option.product_price = option.product.offer_price
                order_option.delivery_price = option.product.delivery_charge
                order_option.tx_price = order_tx_price
                ordered_products.append(order_option)

    if server_tx_amount != tx_amount:
        return Response("amount_mismatched", 400)

    order = Order()
    order.user = request.user
    order.from_cart = from_cart
    order.tx_amount = server_tx_amount
    order.address = request.user.name + "\n" \
                    + request.user.contact_no + "\n" \
                    + request.user.address + "\n" \
                    + str(request.user.pincode) \
                    + request.user.district + "\n" \
                    + request.user.state + "\n"
    order.payment_mode = payment_mode
    order.pending_orders = len(ordered_products)
    order.tx_status = 'INITIATED'
    order.save()

    for ordered_product in ordered_products:
        ordered_product.order = order
        ordered_product.save()

    for option in product_options:
        option.save()

    if payment_mode == 'COD':
        data = {
            "token": "",
            "orderId": order.id,
            "tx_amount": server_tx_amount,
            "appId": CF_ID,
            "orderCurrency": "INR",
        }
        return Response(data)

    headers = {
        'Content-Type': 'application/json',
        'x-client-id': CF_ID,
        'x-client-secret': CF_KEY,
    }

    data = {
        "orderId": str(order.id),
        "orderAmount": server_tx_amount,
        "orderCurrency": "INR",
    }

    response = requests.post("https://test.cashfree.com/api/v2/cftoken/order",
                             headers=headers, data=json.dumps(data))
    if response.json()['status'] == 'OK':
        data = {
            "token": response.json()['cftoken'],
            "orderId": order.id,
            "tx_amount": server_tx_amount,
            "appId": CF_ID,
            "orderCurrency": "INR",
        }
        return Response(data)
    else:
        print(response.json())
        order.tx_status = "FAILED"
        order.tx_msg = "CLICKWELL_SERVER_MSG: Failed to generate cftoken"
        order.save()
        return Response("Something went wrong", 400)


@api_view(['POST'])
def notify_url(request):
    try:
        # Parse incoming data
        data = request.data
        order_id = data.get('orderId')
        tx_status = data.get('txStatus')
        tx_msg = data.get('txMsg', '')
        payment_mode = data.get('paymentMode')
        tx_time = data.get('txTime')
        reference_id = data.get('referenceId', '')
        order_amount = data.get('orderAmount', '')

        # Log the incoming request data for debugging
        print(f"Incoming notify_url data: {data}")

        # Validate incoming order_id
        if not order_id:
            return Response(
                {'status': 'error', 'message': 'Order ID is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Fetch the order based on `orderId`
        if payment_mode == 'COD':
            # Fetch by UUID for COD
            order = get_object_or_404(Order, id=order_id)
        else:
            # Fetch by tx_id for online payments
            order = get_object_or_404(Order, tx_id=order_id)

        # Normalize the order amount for comparison
        order_amount = int(order_amount) / 100 if payment_mode != 'COD' else float(order_amount)
        server_order_amount = float(order.tx_amount)

        # Validate the order amount
        if order_amount != server_order_amount:
            print(f"Order amount mismatch: Received {order_amount}, Expected {server_order_amount}")
            return Response(
                {'status': 'error', 'message': 'Order amount mismatch.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update the order fields
        order.tx_status = tx_status
        order.tx_msg = tx_msg
        order.tx_time = tx_time
        order.payment_mode = payment_mode
        order.tx_id = reference_id
        order.save()

        # Log success
        print(f"Order {order.id} updated successfully with status {tx_status}")

        # Return a success response
        return Response(
            {'status': 'success', 'message': 'Order updated successfully.'},
            status=status.HTTP_200_OK
        )

    except Order.MultipleObjectsReturned:
        print(f"Multiple orders found for orderId: {order_id}")
        return Response(
            {'status': 'error', 'message': f'Multiple orders found for orderId: {order_id}'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    except Order.DoesNotExist:
        print(f"No order found for orderId: {order_id}")
        return Response(
            {'status': 'error', 'message': f'No order found for orderId: {order_id}'},
            status=status.HTTP_404_NOT_FOUND,
        )
    except Exception as e:
        print(f"Exception in notify_url: {str(e)}")
        return Response(
            {'status': 'error', 'message': 'Internal Server Error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(['POST'])
@permission_classes([IsAuthenticatedUser])
def initiate_order(request):
    """
    Handles the creation of an order with support for COD and Razorpay payments.
    Updated to use centralized delivery charge calculation.
    """
    try:
        user = request.user  # Now properly authenticated
        items = request.data.get('items')
        from_cart = request.data.get('from_cart', False)
        tx_amount = request.data.get('tx_amount')
        payment_mode = request.data.get('payment_mode', 'ONLINE')
        address = request.data.get('address', 'No address provided')

        # FIXED: Better validation with detailed error messages
        if not items:
            return Response({
                "error": "data_missing",
                "message": "Items list is required"
            }, status=status.HTTP_400_BAD_REQUEST)

        if tx_amount is None:
            return Response({
                "error": "data_missing",
                "message": "Transaction amount is required"
            }, status=status.HTTP_400_BAD_REQUEST)

        # FIXED: Validate items structure
        if not isinstance(items, list) or len(items) == 0:
            return Response({
                "error": "invalid_data",
                "message": "Items must be a non-empty list"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate each item
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                return Response({
                    "error": "invalid_data",
                    "message": f"Item {i} must be an object"
                }, status=status.HTTP_400_BAD_REQUEST)

            if 'id' not in item or 'quantity' not in item:
                return Response({
                    "error": "invalid_data",
                    "message": f"Item {i} must have 'id' and 'quantity' fields"
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                quantity = int(item['quantity'])
                if quantity <= 0:
                    return Response({
                        "error": "invalid_data",
                        "message": f"Item {i} quantity must be greater than 0"
                    }, status=status.HTTP_400_BAD_REQUEST)
            except (ValueError, TypeError):
                return Response({
                    "error": "invalid_data",
                    "message": f"Item {i} quantity must be a valid number"
                }, status=status.HTTP_400_BAD_REQUEST)

        # FIXED: Better query building logic
        product_ids = [item['id'] for item in items]
        query = Q(id__in=product_ids)

        try:
            product_options = ProductOption.objects.filter(query).select_related('product')

            if not product_options.exists():
                return Response({
                    "error": "products_not_found",
                    "message": "No products found for the given IDs"
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": "database_error",
                "message": f"Error fetching products: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # UPDATED: Calculate items amount first (without individual delivery charges)
        ordered_products = []
        server_items_amount = 0
        product_lookup = {str(option.id): option for option in product_options}

        for item in items:
            item_id = str(item['id'])
            quantity = int(item['quantity'])

            if item_id not in product_lookup:
                return Response({
                    "error": "product_not_found",
                    "message": f"Product with ID {item_id} not found"
                }, status=status.HTTP_404_NOT_FOUND)

            option = product_lookup[item_id]

            # FIXED: Check stock availability
            if option.quantity < quantity:
                return Response({
                    "error": "insufficient_stock",
                    "message": f"Only {option.quantity} units available for {option.product.title}"
                }, status=status.HTTP_400_BAD_REQUEST)

            # FIXED: Better error handling for price calculation
            try:
                offer_price = option.product.offer_price or 0

                # Reduce stock temporarily (will be saved later)
                option.quantity -= quantity

                # Calculate item price (without delivery charge)
                item_price = offer_price * quantity
                server_items_amount += item_price

                # Prepare OrderedProduct (delivery will be added later)
                ordered_product = OrderedProduct(
                    product_option=option,
                    product_price=offer_price,
                    tx_price=item_price,  # Will be updated with delivery portion
                    delivery_price=0,  # Will be calculated centrally
                    quantity=quantity
                )
                ordered_products.append(ordered_product)

            except (AttributeError, TypeError) as e:
                return Response({
                    "error": "price_calculation_error",
                    "message": f"Error calculating price for {option.product.title}: {str(e)}"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # NEW: Apply centralized delivery charge calculation
        try:
            # Use the same logic as calculate_delivery_charge API
            delivery_charge = 30 if server_items_amount < 200 else 0
            server_tx_amount = server_items_amount + delivery_charge

            # Debug logging
            print(f"🔍 Order Calculation Debug:")
            print(f"   Items amount: ₹{server_items_amount}")
            print(f"   Delivery charge: ₹{delivery_charge}")
            print(f"   Server total: ₹{server_tx_amount}")
            print(f"   Client total: ₹{tx_amount}")

        except Exception as e:
            return Response({
                "error": "delivery_calculation_error",
                "message": f"Failed to calculate delivery charge: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # FIXED: Better amount comparison with detailed logging
        try:
            client_amount = float(tx_amount)
            server_amount = float(server_tx_amount)

            # Allow small floating point differences (1 cent tolerance)
            if abs(client_amount - server_amount) > 0.01:
                return Response({
                    "error": "amount_mismatched",
                    "message": f"Amount mismatch: client={client_amount}, server={server_amount}",
                    "client_amount": client_amount,
                    "server_amount": server_amount,
                    "items_amount": server_items_amount,
                    "delivery_charge": delivery_charge,
                    "breakdown": {
                        "items_total": server_items_amount,
                        "delivery_charge": delivery_charge,
                        "calculated_total": server_amount
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

        except (ValueError, TypeError) as e:
            return Response({
                "error": "invalid_amount",
                "message": f"Invalid transaction amount: {str(e)}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # FIXED: Use transaction to ensure data consistency
        try:
            with transaction.atomic():
                # Create the order in the database
                order = Order.objects.create(
                    user=user,
                    tx_amount=server_tx_amount,
                    payment_mode=payment_mode,
                    address=address,
                    from_cart=from_cart,
                    tx_status='INITIATED'
                    # Removed 'pending_orders' as it doesn't exist in the model
                )

                # NEW: Distribute delivery charge among products
                # Simple approach: assign all delivery charge to the first product
                if ordered_products and delivery_charge > 0:
                    ordered_products[0].delivery_price = delivery_charge
                    ordered_products[0].tx_price += delivery_charge

                # Save ordered products
                for op in ordered_products:
                    op.order = order
                    op.save()

                # Save updated stock quantities
                for option in product_options:
                    option.save()

                # Handle COD orders
                if payment_mode.upper() == "COD":
                    order.tx_status = 'SUCCESS'
                    order.tx_msg = 'Cash on Delivery selected'
                    order.payment_mode = 'COD'
                    order.save()

                    return Response({
                        "orderId": str(order.id),
                        "orderAmount": str(server_tx_amount),
                        "paymentMode": "COD",
                        "message": "Order placed successfully with Cash on Delivery.",
                        "breakdown": {
                            "items_total": server_items_amount,
                            "delivery_charge": delivery_charge,
                            "final_total": server_tx_amount
                        }
                    }, status=status.HTTP_200_OK)

                # Handle Razorpay orders
                try:
                    client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
                    amount_in_paise = int(server_tx_amount * 100)

                    razorpay_order_data = {
                        "amount": amount_in_paise,
                        "currency": "INR",
                        "receipt": str(order.id),
                        "payment_capture": 1,
                    }

                    rzp_order = client.order.create(data=razorpay_order_data)

                    # Store Razorpay order ID in the database
                    order.tx_id = rzp_order.get("id")
                    order.save()

                    return Response({
                        "orderId": rzp_order.get("id"),
                        "razorpayKey": RAZORPAY_KEY_ID,
                        "amount": amount_in_paise,
                        "currency": "INR",
                        "clickwellOrderId": str(order.id),
                        "breakdown": {
                            "items_total": server_items_amount,
                            "delivery_charge": delivery_charge,
                            "final_total": server_tx_amount
                        }
                    }, status=status.HTTP_200_OK)

                except Exception as e:
                    order.tx_status = 'FAILED'
                    order.tx_msg = f"Razorpay error: {str(e)}"
                    order.save()

                    return Response({
                        "error": "payment_gateway_error",
                        "message": "Failed to create payment order",
                        "details": str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"Error creating order: {str(e)}")
            return Response({
                "error": "order_creation_failed",
                "message": "Failed to create order",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"Unexpected error in initiate_order: {str(e)}")
        return Response({
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "details": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def orders(request):
    orders = OrderedProduct.objects.filter(order__user=request.user).order_by('-created_at')
    pagination = LimitOffsetPagination()
    queryset = pagination.paginate_queryset(orders, request)
    data = OrderItemSerializer(queryset, many=True).data
    return pagination.get_paginated_response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def orderdetails(request):
    id = request.GET.get('id')
    order = get_object_or_404(OrderedProduct, id=id)
    data = OrderDetailsSerializer(order, many=False).data
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def updaterating(request):
    orderId = request.GET.get('id')
    new_rating = int(request.GET.get('rating'))

    order = get_object_or_404(OrderedProduct, id=orderId)
    initial_rating = order.rating
    order.rating = new_rating

    if initial_rating == 1:
        order.product_option.product.star_1 -= 1
    elif initial_rating == 2:
        order.product_option.product.star_2 -= 1
    elif initial_rating == 3:
        order.product_option.product.star_3 -= 1
    elif initial_rating == 4:
        order.product_option.product.star_4 -= 1
    elif initial_rating == 5:
        order.product_option.product.star_5 -= 1

    if new_rating == 1:
        order.product_option.product.star_1 += 1
    elif new_rating == 2:
        order.product_option.product.star_2 += 1
    elif new_rating == 3:
        order.product_option.product.star_3 += 1
    elif new_rating == 4:
        order.product_option.product.star_4 += 1
    elif new_rating == 5:
        order.product_option.product.star_5 += 1

    order.product_option.product.save()
    order.save()

    return Response('updated')


@api_view(['GET'])
def search(request):
    """
    SINGLE Smart Search API - Finds products even when search term
    doesn't appear in product title

    Example: Search "biscuit" finds Parle, Oreo, Britannia etc.
    """
    query = request.GET.get('query', "").strip().lower()

    if not query:
        return Response({'results': [], 'count': 0})

    pagination = LimitOffsetPagination()

    # Category mappings - products that belong to categories but don't have category name in title
    CATEGORIES = {
        'biscuit': ['parle', 'marie', 'glucose', 'oreo', 'britannia', 'sunfeast',
                    'good day', 'monaco', 'krackjack', 'biscuit'],

        'oil': ['oil', 'safola', 'fortune', 'dhara', 'sunflower', 'mustard',
                'coconut', 'olive', 'groundnut'],

        'rice': ['rice', 'basmati', 'india gate', 'kohinoor', 'fortune'],

        'chocolate': ['chocolate', 'cadbury', 'dairy milk', 'silk', 'kitkat',
                      '5 star', 'gems', 'perk', 'eclairs'],

        'tea': ['tea', 'tata', 'red label', 'lipton', 'green tea'],

        'soap': ['soap', 'lux', 'dove', 'pears', 'lifebuoy', 'dettol',
                 'santoor', 'cinthol', 'rexona'],

        'shampoo': ['shampoo', 'pantene', 'tresemme', 'sunsilk'],

        'washing powder': ['surf', 'ariel', 'tide', 'wheel', 'nirma', 'ghadi', 'rin', 'washing'],

        'toothpaste': ['toothpaste', 'colgate', 'pepsodent', 'close up', 'sensodyne', 'dabur'],

        'dal': ['dal', 'moong', 'chana', 'toor', 'urad'],

        'atta': ['atta', 'flour', 'chakki', 'aashirvaad', 'fortune', 'patanjali'],

        'milk': ['milk', 'amul', 'dairy', 'cream'],

        'noodles': ['noodles', 'maggi', 'yippee', 'pasta', 'hakka'],

        'snacks': ['lays', 'kurkure', 'haldiram', 'namkeen', 'mixture', 'bhujia', 'chips'],

        'coffee': ['coffee', 'nescafe', 'bru', 'instant'],

        'sauce': ['sauce', 'kissan', 'maggi', 'tomato', 'chilli'],

        'pickle': ['pickle', 'achar', 'patanjali'],
        'achar': ['pickle', 'achar', 'patanjali','nilons'],

        'honey': ['honey', 'dabur', 'patanjali'],

        'salt': ['salt', 'tata', 'rock salt'],

        'ghee': ['ghee', 'amul', 'patanjali'],

        'butter': ['butter', 'amul', 'britannia'],

        'bread': ['bread', 'britannia'],

        'hair oil': ['hair', 'karpin', 'hair & care', 'sesa', 'livon', 'parachute', 'amla', 'shanti'],
    }

    # Build search query
    search_queries = []

    # 1. Direct search (exact keyword matches)
    keywords = [kw.strip() for kw in query.split() if kw.strip()]
    direct_search = Q()
    for keyword in keywords:
        direct_search |= Q(product__title__icontains=keyword) | Q(option__icontains=keyword)
    search_queries.append(('direct', direct_search))

    # 2. Category-based search (semantic matching)
    category_search = Q()
    matched_categories = []

    for category, terms in CATEGORIES.items():
        # Check if query matches category name or is found in category
        if query == category or category in query or query in category:
            matched_categories.append(category)
            for term in terms:
                category_search |= Q(product__title__icontains=term) | Q(option__icontains=term)

    if category_search:
        search_queries.append(('category', category_search))

    # 3. Partial matching for brand/product detection
    partial_search = Q()
    for category, terms in CATEGORIES.items():
        for term in terms:
            if len(query) >= 3 and (query in term.lower() or term.lower() in query):
                partial_search |= Q(product__title__icontains=term) | Q(option__icontains=term)

    if partial_search:
        search_queries.append(('partial', partial_search))

    # Combine all searches
    combined_search = Q()
    for search_type, search_q in search_queries:
        combined_search |= search_q

    if not combined_search:
        return Response({'results': [], 'count': 0})

    # Smart ranking system
    ranking_cases = []

    # Highest priority: Exact matches
    for i, keyword in enumerate(keywords):
        ranking_cases.extend([
            When(product__title__iexact=keyword, then=Value(1000 + i)),
            When(option__iexact=keyword, then=Value(950 + i)),
            When(product__title__istartswith=keyword, then=Value(900 + i)),
            When(product__title__icontains=keyword, then=Value(800 + i)),
            When(option__icontains=keyword, then=Value(750 + i)),
        ])

    # High priority: Category matches (only if categories were matched)
    if matched_categories:
        score = 600
        for category in matched_categories:
            if category in CATEGORIES:
                for term in CATEGORIES[category]:
                    ranking_cases.extend([
                        When(product__title__icontains=term, then=Value(score)),
                        When(option__icontains=term, then=Value(score - 25)),
                    ])
                    score -= 1  # Slight decrease for each term

    # Medium priority: Partial matches (only if not empty)
    if partial_search:
        ranking_cases.append(When(partial_search, then=Value(400)))

    # Execute search with ranking (only if we have ranking cases)
    if ranking_cases:
        products = ProductOption.objects.filter(combined_search).annotate(
            relevance_score=Case(
                *ranking_cases,
                default=Value(0),
                output_field=IntegerField()
            )
        ).order_by(
            '-relevance_score',
            'product__title',
            'option'
        ).distinct()
    else:
        # Fallback without ranking if no ranking cases
        products = ProductOption.objects.filter(combined_search).order_by(
            'product__title',
            'option'
        ).distinct()

    # Apply pagination
    result_page = pagination.paginate_queryset(products, request)
    data = WishlistSerializer(result_page, many=True).data

    return pagination.get_paginated_response(data)


@api_view(['POST'])
@permission_classes([IsAuthenticatedUser])
def updateinfo(request):
    phone = request.data.get('phone')
    email = request.data.get('email')
    name = request.data.get('fullname')
    password = request.data.get('password')

    if not email or not phone or not name or not password:
        return Response('params_missing', 400)

    if check_password(password, request.user.password):
        if phone != request.user.phone:
            if User.objects.filter(phone=phone).exists():
                return Response('phone already exists', 400)
            otp_obj = get_object_or_404(Otp, phone=phone, verified=True)
            otp_obj.delete()

        if email != request.user.email:
            if User.objects.filter(email=email).exists():
                return Response('email already exists', 400)

        user = request.user
        user.phone = phone
        user.email = email
        user.fullname = name
        user.save()
        return Response('updated_successfully')
    else:
        return Response('incorrect_password', 401)


@api_view(['POST'])
@permission_classes([IsAuthenticatedUser])
def update_phone_request_otp(request):
    phone = request.data.get('phone')
    password = request.data.get('password')

    if check_password(password, request.user.password):
        if not phone:
            return Response('params_missing', 400)

        if User.objects.filter(phone=phone).exists():
            return Response('phone already exists', 400)
        else:
            return send_otp(phone)
    else:
        return Response('incorrect_password', 401)


@api_view(['POST'])
@permission_classes([IsAuthenticatedUser])
def change_password(request):
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')

    if check_password(old_password, request.user.password):
        request.user.password = make_password(new_password)
        request.user.save()
        Token.objects.filter(user=request.user).delete()
        return Response('password_updated')
    else:
        return Response('incorrect_password', 401)



@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def notifications(request):
    pagination = LimitOffsetPagination()

    request.user.notifications_set.filter(seen=False).update(seen=True)

    notifications_set = request.user.notifications_set.all().order_by('-created_at')

    queryset = pagination.paginate_queryset(notifications_set, request)

    data = NotificationSerializer(queryset, many=True).data
    return pagination.get_paginated_response(data)




@api_view(['POST'])
def forgot_password(request):
    phone = request.data.get('phone')

    if not phone:
        return Response({'error': 'Phone number is missing.'}, status=400)

    try:
        user = User.objects.get(phone=phone)
        # Proceed to send OTP to the user's phone
        send_otp(phone)  # Assuming this function is defined elsewhere and handles OTP sending
        return Response({'message': 'OTP sent successfully.'}, status=200)
    except ObjectDoesNotExist:
        return Response({'error': 'Phone number not found.'}, status=404)


def privacy_policy(request):
    return render(request, 'privacy_policy.html')




class PrivacyPolicyAPIView(APIView):
    def get(self, request):
        response = render(request, 'privacy_policy.html')
        html_content = response.content.decode('utf-8')
        data = {
            'content': html_content
        }
        return Response(data)


def contact_us(request):
    return render(request, 'contact_us.html')

class ContactUsAPIView(APIView):
    def get(self,request):
        response = render(request,'contact_us.html')
        html_contact = response.content.decode('utf-8')
        data = {
            'content': html_contact
        }
        return Response(data)


@api_view(['POST'])
def forgotpassword(request):
    phone = request.data.get('phone')

    if not phone:
        return Response({'error': 'Phone number is missing.'}, status=400)

    try:
        # Validate and retrieve the user by phone
        user = User.objects.get(phone=phone)
        # Assuming send_otp function returns True on success, False otherwise
        if send_otp(phone):  # This sends the OTP and checks if sending was successful
            return Response({'message': 'OTP sent successfully.'}, status=200)
        else:
            # Handling case where OTP sending failed
            return Response({'error': 'Failed to send OTP.'}, status=500)
    except User.DoesNotExist:
        return Response({'error': 'Phone number not found.'}, status=404)




@api_view(['POST'])
def verify_pass_otp(request): #Todo True
    phone = request.data.get('phone')
    otp = request.data.get('otp')

    # Ensure otp is an integer
    try:
        otp = int(otp)
    except ValueError:
        return Response('OTP must be a number.', status=400)

    otp_obj = get_object_or_404(Otp, phone=phone, verified=False)

    if otp_obj.validity.replace(tzinfo=None) > datetime.datetime.utcnow():
        if otp_obj.otp == otp:
            otp_obj.verified = True
            otp_obj.save()
            return Response('OTP verified successfully.')
        else:
            return Response('Incorrect OTP.', status=400)
    else:
        return Response('OTP expired.', status=400)






logger = logging.getLogger(__name__)
class ChangePasswordView(APIView): #todo TRUE
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        new_password = request.data.get('new_password')
        logger.info(f"Attempting to change password for user: {request.user.username}")

        if not new_password:
            return Response({'error': 'New password is required.'}, status=status.HTTP_400_BAD_REQUEST)

        request.user.password = make_password(new_password)
        request.user.save()

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)


@api_view(['POST']) #todo true API
def newpassword(request):
    phone = request.data.get('phone')
    password1 = request.data.get('password1')
    password2 = request.data.get('password2')

    # Attempt to find the user by phone number
    user = User.objects.filter(phone=phone).first()
    if not user:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Check password length
    if len(password1) < 8:
        return Response({'error': 'Password length must be at least 8 characters!'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if passwords match
    if password1 != password2:
        return Response({'error': 'Passwords do not match!'}, status=status.HTTP_400_BAD_REQUEST)

    # Set the new password
    user.password = make_password(password1)
    user.save()

    # Log the user out from all sessions by deleting their token
    Token.objects.filter(user=user).delete()

    # Return a success message
    return Response({'message': 'Password updated successfully.'}, status=status.HTTP_200_OK)





# @api_view(['GET'])
# def order_list(request):
#     orders = Order.objects.all().order_by('-created_at')
#     serializer = OrderDetailSerializer(orders, many=True)
#     return Response({"data": serializer.data})

@api_view(['GET'])
def ordered_product_list(request):
    """
    API endpoint for paginated ordered products list
    Supports: page, page_size, status, search, from_date, to_date parameters
    """
    try:
        # Get pagination parameters
        page = request.GET.get('page', 1)
        page_size = request.GET.get('page_size', 15)  # Default to 15 per page

        # Convert to integers with validation
        try:
            page = int(page)
            page_size = int(page_size)
        except (ValueError, TypeError):
            return Response({
                'error': 'Invalid page or page_size parameter. Must be integers.',
                'data': [],
                'total_count': 0,
                'current_page': 1,
                'total_pages': 1,
                'has_next': False,
                'has_previous': False
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate page_size limits (prevent abuse)
        if page_size < 1:
            page_size = 15
        elif page_size > 100:  # Maximum 100 items per page
            page_size = 100

        if page < 1:
            page = 1

        # Base queryset - FIXED: removed related_products prefetch
        queryset = OrderedProduct.objects.select_related(
            'order__user'  # Only keep existing relationships
        ).all().order_by('-created_at')

        # Apply filters
        # Status filter
        status_filter = request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status__icontains=status_filter)

        # Search filter (search in product title, user name, etc.)
        search_query = request.GET.get('search')
        if search_query:
            queryset = queryset.filter(
                Q(product_title__icontains=search_query) |
                Q(order__user__first_name__icontains=search_query) |
                Q(order__user__last_name__icontains=search_query) |
                Q(order__user__email__icontains=search_query)
            )

        # Date range filters
        from_date = request.GET.get('from_date')
        to_date = request.GET.get('to_date')

        if from_date:
            try:
                from_date = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
                queryset = queryset.filter(created_at__gte=from_date)
            except ValueError:
                pass  # Ignore invalid date format

        if to_date:
            try:
                to_date = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
                queryset = queryset.filter(created_at__lte=to_date)
            except ValueError:
                pass  # Ignore invalid date format

        # Get total count before pagination
        total_count = queryset.count()

        # Calculate total pages
        total_pages = math.ceil(total_count / page_size) if total_count > 0 else 1

        # Apply pagination
        paginator = Paginator(queryset, page_size)

        try:
            paginated_orders = paginator.page(page)
        except PageNotAnInteger:
            # If page is not an integer, deliver first page
            paginated_orders = paginator.page(1)
            page = 1
        except EmptyPage:
            # If page is out of range, deliver last page
            page = paginator.num_pages
            paginated_orders = paginator.page(page)

        # Serialize the data
        serializer = ItemOrderSerializer(
            paginated_orders.object_list,
            many=True,
            context={'request': request}
        )

        # Prepare response with pagination metadata
        response_data = {
            'data': serializer.data,
            'total_count': total_count,
            'current_page': page,
            'total_pages': total_pages,
            'page_size': page_size,
            'has_next': paginated_orders.has_next(),
            'has_previous': paginated_orders.has_previous(),
            'next_page': page + 1 if paginated_orders.has_next() else None,
            'previous_page': page - 1 if paginated_orders.has_previous() else None,
            'count_on_page': len(paginated_orders.object_list),
        }

        # Add debug info (remove in production)
        if request.GET.get('debug'):
            response_data['debug'] = {
                'requested_page': request.GET.get('page', 1),
                'requested_page_size': request.GET.get('page_size', 15),
                'applied_filters': {
                    'status': status_filter,
                    'search': search_query,
                    'from_date': str(from_date) if from_date else None,
                    'to_date': str(to_date) if to_date else None,
                },
                'queryset_count_before_pagination': total_count,
                'model_fields': [field.name for field in OrderedProduct._meta.fields],
            }

        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        # Log the error in production
        print(f"Error in ordered_product_list: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

        return Response({
            'error': 'An error occurred while fetching orders.',
            'data': [],
            'total_count': 0,
            'current_page': 1,
            'total_pages': 1,
            'has_next': False,
            'has_previous': False
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Alternative minimal version if you're still getting errors
@api_view(['GET'])
def ordered_product_list_minimal(request):
    """
    Minimal version for testing - gradually add features once this works
    """
    try:
        # Get pagination parameters
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 15))

        # Validate
        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 15

        # Simple queryset - just get the orders
        queryset = OrderedProduct.objects.all().order_by('-created_at')

        # Get total count
        total_count = queryset.count()

        # Calculate pagination
        total_pages = math.ceil(total_count / page_size) if total_count > 0 else 1
        start = (page - 1) * page_size
        end = start + page_size

        # Get the slice of data
        orders = queryset[start:end]

        # Serialize
        serializer = ItemOrderSerializer(orders, many=True, context={'request': request})

        # Response
        return Response({
            'data': serializer.data,
            'total_count': total_count,
            'current_page': page,
            'total_pages': total_pages,
            'page_size': page_size,
            'has_next': page < total_pages,
            'has_previous': page > 1,
            'count_on_page': len(orders),
        })

    except Exception as e:
        print(f"Error in minimal ordered_product_list: {str(e)}")
        return Response({
            'error': str(e),
            'data': [],
            'total_count': 0,
            'current_page': 1,
            'total_pages': 1,
            'has_next': False,
            'has_previous': False
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['POST'])
def update_order_status(request):
    ordered_product_id = request.data.get('id')
    new_status = request.data.get('status')

    if not ordered_product_id or not new_status:
        return Response({
            'success': False,
            'error': 'Missing parameters',
            'message': 'Both id and status are required'
        }, status=http_status.HTTP_400_BAD_REQUEST)

    # Validate status
    valid_statuses = ['ORDERED', 'OUT_FOR_DELIVERY', 'DELIVERED', 'CANCELLED']
    if new_status not in valid_statuses:
        return Response({
            'success': False,
            'error': 'Invalid status',
            'message': f'Status must be one of: {", ".join(valid_statuses)}'
        }, status=http_status.HTTP_400_BAD_REQUEST)

    try:
        ordered_product = OrderedProduct.objects.get(id=ordered_product_id)
        old_status = ordered_product.status
        ordered_product.status = new_status
        ordered_product.save()

        # Send notification if delivered
        if new_status == 'DELIVERED':
            try:
                user = ordered_product.order.user
                title = f"ORDER {new_status}"
                body = f"Your {ordered_product.product_option} has been {new_status}."
                image = ordered_product.product_option.images_set.first().image if ordered_product.product_option.images_set.exists() else None
                send_user_notification(user, title, body, image)
            except Exception as e:
                print(f"Error sending notification: {e}")

        serializer = OrderItemSerializer(ordered_product, context={'request': request})

        return Response({
            'success': True,
            'message': f'Status updated successfully from {old_status} to {new_status}',
            'product': serializer.data
        }, status=http_status.HTTP_200_OK)

    except OrderedProduct.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Ordered product not found',
            'message': f'No ordered product found with id: {ordered_product_id}'
        }, status=http_status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error updating order status: {str(e)}")
        return Response({
            'success': False,
            'error': 'Internal server error',
            'message': 'An error occurred while updating the order status'
        }, status=http_status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticatedUser])
def delete_account(request):
    """
    Deletes the authenticated user's account.
    """
    user = request.user
    try:
        user.delete()
        return Response("Account deleted successfully")
    except Exception as e:
        return Response({"error": str(e)}, status=500)


def fast2sms_verification(request):
    return render(request, "fast2sms_verification.html")



@api_view(['GET'])
def get_phone_number(request):
    contact = ContactInfo.objects.first()
    number = contact.phone_number.strip() if contact and contact.phone_number else '9999999999'
    return Response({'phone_number': number})

@api_view(['GET'])
def all_products(request):
    products = Product.objects.all().order_by('-created_at')
    data = ProductSerializer(products, many=True, context={'request': request}).data
    return Response(data)


@api_view(['PUT'])
@csrf_exempt
def update_product(request, product_id):
    """
    Update product details
    URL: /api/products/<product_id>/update/
    """
    try:
        product = Product.objects.get(id=product_id)

        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Update product fields
        product.title = data.get('title', product.title)
        product.description = data.get('description', product.description)
        product.price = data.get('price', product.price)
        product.offer_price = data.get('offer_price', product.offer_price)
        product.delivery_charge = data.get('delivery_charge', product.delivery_charge)
        product.cod = data.get('cod', product.cod)

        product.save()

        # Return updated product
        serializer = ProductSerializer(product, context={'request': request})
        return JsonResponse(serializer.data)

    except Product.DoesNotExist:
        return JsonResponse({'error': 'Product not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['PUT'])
@csrf_exempt
def update_product_option(request, option_id):
    """
    Update product option details
    URL: /api/product-options/<option_id>/update/
    """
    try:
        option = ProductOption.objects.get(id=option_id)

        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Update option fields
        option.option = data.get('option', option.option)
        option.quantity = data.get('quantity', option.quantity)

        option.save()

        # Return updated option
        serializer = ProductOptionSerializer(option, context={'request': request})
        return JsonResponse(serializer.data)

    except ProductOption.DoesNotExist:
        return JsonResponse({'error': 'Product option not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['POST'])
@csrf_exempt
def upload_product_image(request):
    """
    Upload new product image
    URL: /api/product-images/upload/
    """
    try:
        option_id = request.POST.get('product_option')
        position = int(request.POST.get('position', 0))
        image_file = request.FILES.get('image')

        if not image_file:
            return JsonResponse({'error': 'No image file provided'}, status=400)

        if not option_id:
            return JsonResponse({'error': 'Product option ID is required'}, status=400)

        # Get the product option
        try:
            option = ProductOption.objects.get(id=option_id)
        except ProductOption.DoesNotExist:
            return JsonResponse({'error': 'Product option not found'}, status=404)

        # Create new product image
        product_image = ProductImage.objects.create(
            product_option=option,
            image=image_file,
            position=position
        )

        # Return image information
        return JsonResponse({
            'id': product_image.id,
            'image': request.build_absolute_uri(product_image.image.url),
            'position': product_image.position,
            'product_option': str(option.id)
        }, status=201)

    except ValueError as e:
        return JsonResponse({'error': f'Invalid position value: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['DELETE'])
@csrf_exempt
def delete_product_image(request, image_id):
    """
    Delete product image
    URL: /api/product-images/<image_id>/delete/
    """
    try:
        # Try to find image by ID (if you have proper image IDs)
        try:
            image = ProductImage.objects.get(id=image_id)
        except (ProductImage.DoesNotExist, ValueError):
            # If direct ID doesn't work, try to parse the composite ID
            # Format: image_{option_id}_{index}
            if image_id.startswith('image_'):
                parts = image_id.split('_')
                if len(parts) >= 3:
                    option_id = parts[1]
                    index = int(parts[2])

                    option = ProductOption.objects.get(id=option_id)
                    images = option.images_set.all().order_by('position')

                    if index < len(images):
                        image = images[index]
                    else:
                        return JsonResponse({'error': 'Image index out of range'}, status=404)
                else:
                    return JsonResponse({'error': 'Invalid image ID format'}, status=400)
            else:
                return JsonResponse({'error': 'Image not found'}, status=404)

        # Delete the image file from storage
        if image.image:
            try:
                image.image.delete(save=False)
            except:
                pass  # Continue even if file deletion fails

        # Delete the database record
        image.delete()

        return JsonResponse({'message': 'Image deleted successfully'}, status=200)

    except ProductOption.DoesNotExist:
        return JsonResponse({'error': 'Product option not found'}, status=404)
    except ValueError as e:
        return JsonResponse({'error': f'Invalid image ID: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['GET'])
def get_product_details(request, product_id):
    """
    Get detailed product information
    URL: /api/products/<product_id>/
    """
    try:
        product = Product.objects.get(id=product_id)
        serializer = ProductSerializer(product, context={'request': request})
        return JsonResponse(serializer.data)

    except Product.DoesNotExist:
        return JsonResponse({'error': 'Product not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['POST'])
@csrf_exempt
def create_product(request):
    """
    Create a new product
    URL: /api/products/create/
    """
    try:
        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Get category
        from backend.models import Category
        category = Category.objects.get(id=data.get('category'))

        # Create product
        product = Product.objects.create(
            category=category,
            title=data.get('title'),
            description=data.get('description', ''),
            price=data.get('price'),
            offer_price=data.get('offer_price'),
            delivery_charge=data.get('delivery_charge', 0),
            cod=data.get('cod', False)
        )

        serializer = ProductSerializer(product, context={'request': request})
        return JsonResponse(serializer.data, status=201)

    except Category.DoesNotExist:
        return JsonResponse({'error': 'Category not found'}, status=404)
    except KeyError as e:
        return JsonResponse({'error': f'Missing required field: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['DELETE'])
@csrf_exempt
def delete_product(request, product_id):
    """
    Delete a product
    URL: /api/products/<product_id>/delete/
    """
    try:
        product = Product.objects.get(id=product_id)

        # Delete associated images
        for option in product.options_set.all():
            for image in option.images_set.all():
                if image.image:
                    try:
                        image.image.delete(save=False)
                    except:
                        pass

        # Delete the product (cascade will handle related objects)
        product.delete()

        return JsonResponse({'message': 'Product deleted successfully'}, status=200)

    except Product.DoesNotExist:
        return JsonResponse({'error': 'Product not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

################ new APis for ClickwellXvijayshree app

@api_view(['POST'])
@csrf_exempt
def create_product_option(request):
    """
    Create a new product option
    URL: /api/product-options/create/
    """
    try:
        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Get the product
        product = Product.objects.get(id=data.get('product'))

        # Create product option
        product_option = ProductOption.objects.create(
            product=product,
            option=data.get('option'),
            quantity=data.get('quantity', 0)
        )

        serializer = ProductOptionSerializer(product_option, context={'request': request})
        return JsonResponse(serializer.data, status=201)

    except Product.DoesNotExist:
        return JsonResponse({'error': 'Product not found'}, status=404)
    except KeyError as e:
        return JsonResponse({'error': f'Missing required field: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['GET'])
def get_categories(request):
    """
    Get all categories
    URL: /api/categories/
    """
    try:
        categories = Category.objects.all().order_by('position')
        data = CategorySerializer(categories, many=True).data
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# Updated create_product function with better error handling
@api_view(['POST'])
@csrf_exempt
def create_product_enhanced(request):
    """
    Create a new product with enhanced error handling
    URL: /api/products/create/
    """
    try:
        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Validate required fields
        required_fields = ['title', 'price', 'offer_price', 'category']
        for field in required_fields:
            if field not in data:
                return JsonResponse({'error': f'Missing required field: {field}'}, status=400)

        # Get category
        try:
            category = Category.objects.get(id=data.get('category'))
        except Category.DoesNotExist:
            return JsonResponse({'error': 'Category not found'}, status=404)

        # Validate numeric fields
        try:
            price = int(data.get('price'))
            offer_price = int(data.get('offer_price'))
            delivery_charge = int(data.get('delivery_charge', 0))
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Price fields must be valid numbers'}, status=400)

        if price < 0 or offer_price < 0 or delivery_charge < 0:
            return JsonResponse({'error': 'Price fields must be non-negative'}, status=400)

        # Create product
        product = Product.objects.create(
            category=category,
            title=data.get('title'),
            description=data.get('description', ''),
            price=price,
            offer_price=offer_price,
            delivery_charge=delivery_charge,
            cod=data.get('cod', False)
        )

        serializer = ProductSerializer(product, context={'request': request})
        return JsonResponse(serializer.data, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Updated product endpoints with better validation
@api_view(['PUT'])
@csrf_exempt
def update_product_enhanced(request, product_id):
    """
    Update product details with enhanced validation
    URL: /api/products/<product_id>/update/
    """
    try:
        product = Product.objects.get(id=product_id)

        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Validate numeric fields if provided
        numeric_fields = ['price', 'offer_price', 'delivery_charge']
        for field in numeric_fields:
            if field in data:
                try:
                    value = int(data[field])
                    if value < 0:
                        return JsonResponse({'error': f'{field} must be non-negative'}, status=400)
                except (ValueError, TypeError):
                    return JsonResponse({'error': f'{field} must be a valid number'}, status=400)

        # Update product fields
        product.title = data.get('title', product.title)
        product.description = data.get('description', product.description)
        product.price = data.get('price', product.price)
        product.offer_price = data.get('offer_price', product.offer_price)
        product.delivery_charge = data.get('delivery_charge', product.delivery_charge)
        product.cod = data.get('cod', product.cod)

        product.save()

        # Return updated product
        serializer = ProductSerializer(product, context={'request': request})
        return JsonResponse(serializer.data)

    except Product.DoesNotExist:
        return JsonResponse({'error': 'Product not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['PUT'])
@csrf_exempt
def update_product_option_enhanced(request, option_id):
    """
    Update product option details with enhanced validation
    URL: /api/product-options/<option_id>/update/
    """
    try:
        option = ProductOption.objects.get(id=option_id)

        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        # Validate quantity if provided
        if 'quantity' in data:
            try:
                quantity = int(data['quantity'])
                if quantity < 0:
                    return JsonResponse({'error': 'Quantity must be non-negative'}, status=400)
            except (ValueError, TypeError):
                return JsonResponse({'error': 'Quantity must be a valid number'}, status=400)

        # Update option fields
        option.option = data.get('option', option.option)
        option.quantity = data.get('quantity', option.quantity)

        option.save()

        # Return updated option
        serializer = ProductOptionSerializer(option, context={'request': request})
        return JsonResponse(serializer.data)

    except ProductOption.DoesNotExist:
        return JsonResponse({'error': 'Product option not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['POST'])
@csrf_exempt
def upload_product_image_enhanced(request):
    """
    Upload new product image with enhanced validation
    URL: /api/product-images/upload/
    """
    try:
        option_id = request.POST.get('product_option')
        position = request.POST.get('position', 0)
        image_file = request.FILES.get('image')

        if not image_file:
            return JsonResponse({'error': 'No image file provided'}, status=400)

        if not option_id:
            return JsonResponse({'error': 'Product option ID is required'}, status=400)

        # Validate position
        try:
            position = int(position)
            if position < 0:
                return JsonResponse({'error': 'Position must be non-negative'}, status=400)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Position must be a valid number'}, status=400)

        # Get the product option
        try:
            option = ProductOption.objects.get(id=option_id)
        except ProductOption.DoesNotExist:
            return JsonResponse({'error': 'Product option not found'}, status=404)

        # Validate image file
        if image_file.size > 5 * 1024 * 1024:  # 5MB limit
            return JsonResponse({'error': 'Image file too large (max 5MB)'}, status=400)

        allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp']
        if image_file.content_type not in allowed_types:
            return JsonResponse({'error': 'Invalid image format. Allowed: JPEG, PNG, WebP'}, status=400)

        # Create new product image
        product_image = ProductImage.objects.create(
            product_option=option,
            image=image_file,
            position=position
        )

        # Return image information
        return JsonResponse({
            'id': product_image.id,
            'image': request.build_absolute_uri(product_image.image.url),
            'position': product_image.position,
            'product_option': str(option.id)
        }, status=201)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['DELETE'])
@csrf_exempt
def delete_product_image_enhanced(request, image_id):
    """
    Delete product image with enhanced error handling
    URL: /api/product-images/<image_id>/delete/
    """
    try:
        # Try to find image by ID (if you have proper image IDs)
        try:
            image = ProductImage.objects.get(id=image_id)
        except (ProductImage.DoesNotExist, ValueError):
            # If direct ID doesn't work, try to parse the composite ID
            # Format: image_{option_id}_{index}
            if image_id.startswith('image_'):
                parts = image_id.split('_')
                if len(parts) >= 3:
                    option_id = parts[1]
                    index = int(parts[2])

                    try:
                        option = ProductOption.objects.get(id=option_id)
                        images = option.images_set.all().order_by('position')

                        if index < len(images):
                            image = images[index]
                        else:
                            return JsonResponse({'error': 'Image index out of range'}, status=404)
                    except ProductOption.DoesNotExist:
                        return JsonResponse({'error': 'Product option not found'}, status=404)
                    except ValueError:
                        return JsonResponse({'error': 'Invalid image index'}, status=400)
                else:
                    return JsonResponse({'error': 'Invalid image ID format'}, status=400)
            else:
                return JsonResponse({'error': 'Image not found'}, status=404)

        # Delete the image file from storage
        if image.image:
            try:
                image.image.delete(save=False)
            except:
                pass  # Continue even if file deletion fails

        # Delete the database record
        image.delete()

        return JsonResponse({'message': 'Image deleted successfully'}, status=200)

    except ValueError as e:
        return JsonResponse({'error': f'Invalid image ID: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Additional utility function for bulk operations
@api_view(['POST'])
@csrf_exempt
def bulk_update_stock(request):
    """
    Bulk update stock quantities for multiple products
    URL: /api/bulk-update-stock/
    """
    try:
        data = request.data if hasattr(request, 'data') else json.loads(request.body)

        if 'updates' not in data:
            return JsonResponse({'error': 'Updates array is required'}, status=400)

        updated_count = 0
        errors = []

        for update in data['updates']:
            try:
                option_id = update.get('option_id')
                quantity = update.get('quantity')

                if not option_id or quantity is None:
                    errors.append(f"Missing option_id or quantity in update")
                    continue

                option = ProductOption.objects.get(id=option_id)
                option.quantity = int(quantity)
                option.save()
                updated_count += 1

            except ProductOption.DoesNotExist:
                errors.append(f"Product option {option_id} not found")
            except (ValueError, TypeError):
                errors.append(f"Invalid quantity for option {option_id}")
            except Exception as e:
                errors.append(f"Error updating option {option_id}: {str(e)}")

        return JsonResponse({
            'message': f'Successfully updated {updated_count} product options',
            'updated_count': updated_count,
            'errors': errors
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['POST'])
def update_all_order_products_status_enhanced(request):
    """
    Enhanced API to update all products in an order to the same status

    Expected payload:
    {
        "product_id": "uuid-of-any-product-in-order",
        "status": "DELIVERED",
        "update_mode": "all" // "all", "others", or "selective"
    }
    """
    product_id = request.data.get('product_id')
    new_status = request.data.get('status')
    update_mode = request.data.get('update_mode', 'all')

    # Validate required parameters
    if not product_id or not new_status:
        return Response({
            'error': 'Both product_id and status are required',
            'valid_statuses': ['ORDERED', 'OUT_FOR_DELIVERY', 'DELIVERED', 'CANCELLED']
        }, status=http_status.HTTP_400_BAD_REQUEST)

    # Validate status value
    valid_statuses = ['ORDERED', 'OUT_FOR_DELIVERY', 'DELIVERED', 'CANCELLED']
    if new_status not in valid_statuses:
        return Response({
            'error': 'Invalid status',
            'valid_statuses': valid_statuses
        }, status=http_status.HTTP_400_BAD_REQUEST)

    try:
        # Find the reference product to get its order
        reference_product = OrderedProduct.objects.get(id=product_id)
        order_id = reference_product.order.id

        # Get all products in the same order based on update mode
        if update_mode == 'all':
            # Update ALL products in the order
            products_to_update = OrderedProduct.objects.filter(order__id=order_id)
        elif update_mode == 'others':
            # Update all OTHER products (excluding the reference product)
            products_to_update = OrderedProduct.objects.filter(
                order__id=order_id
            ).exclude(id=product_id)
        else:
            return Response({
                'error': 'Invalid update_mode. Must be "all" or "others"'
            }, status=http_status.HTTP_400_BAD_REQUEST)

        if not products_to_update.exists():
            return Response({
                'message': 'No products found to update',
                'order_id': str(order_id)
            }, status=http_status.HTTP_200_OK)

        # Use transaction to ensure all updates succeed or fail together
        with transaction.atomic():
            updated_count = products_to_update.update(status=new_status)

            # Get all products in the order for response
            all_order_products = OrderedProduct.objects.filter(order__id=order_id)

            # Send notifications for status updates if delivered
            if new_status == 'DELIVERED':
                for product in products_to_update:
                    try:
                        user = product.order.user
                        title = f"ORDER {new_status}"
                        body = f"Your {product.product_option} has been {new_status}."
                        image = product.product_option.images_set.first().image if product.product_option.images_set.exists() else None
                        send_user_notification(user, title, body, image)
                    except Exception as e:
                        print(f"Error sending notification: {e}")

            # Log the bulk update
            logger.info(f"Bulk status update: Order {order_id}, {updated_count} products updated to {new_status}")

            # Serialize all products in the order
            serializer = ItemOrderSerializer(all_order_products, many=True, context={'request': request})

            return Response({
                'success': True,
                'message': f'Successfully updated {updated_count} products to {new_status}',
                'order_id': str(order_id),
                'reference_product_id': str(product_id),
                'updated_count': updated_count,
                'new_status': new_status,
                'update_mode': update_mode,
                'all_order_products': serializer.data
            }, status=http_status.HTTP_200_OK)

    except OrderedProduct.DoesNotExist:
        return Response({
            'error': 'Product not found'
        }, status=http_status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error in bulk status update: {str(e)}")
        return Response({
            'error': 'An error occurred while updating order status',
            'details': str(e)
        }, status=http_status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def update_order_with_confirmation(request):
    """
    API that handles order status updates with confirmation for bulk actions

    Expected payload:
    {
        "product_id": "uuid",
        "status": "DELIVERED",
        "apply_to_all": true,  // If true, applies to all products in order
        "confirmed": false     // Set to true if user confirmed bulk action
    }
    """
    product_id = request.data.get('product_id')
    new_status = request.data.get('status')
    apply_to_all = request.data.get('apply_to_all', False)
    confirmed = request.data.get('confirmed', False)

    if not product_id or not new_status:
        return Response({
            'error': 'Both product_id and status are required'
        }, status=http_status.HTTP_400_BAD_REQUEST)

    try:
        # Find the reference product
        reference_product = OrderedProduct.objects.get(id=product_id)
        order_id = reference_product.order.id

        # Get all products in the same order
        all_order_products = OrderedProduct.objects.filter(order__id=order_id)
        total_products = all_order_products.count()

        # If applying to all and there are multiple products, check if confirmation is needed
        if apply_to_all and total_products > 1 and not confirmed:
            # Return confirmation request
            other_products = all_order_products.exclude(id=product_id)
            other_products_data = []

            for product in other_products:
                other_products_data.append({
                    'id': str(product.id),
                    'title': product.product_option.product.title,
                    'option': product.product_option.option,
                    'current_status': product.status,
                    'quantity': product.quantity
                })

            return Response({
                'confirmation_required': True,
                'message': f'This will update {total_products} products in this order to "{new_status}". Do you want to continue?',
                'order_id': str(order_id),
                'total_products': total_products,
                'other_products': other_products_data,
                'new_status': new_status
            }, status=http_status.HTTP_200_OK)

        # Proceed with update
        if apply_to_all:
            # Update all products in the order
            with transaction.atomic():
                updated_count = all_order_products.update(status=new_status)

                # Send notifications if delivered
                if new_status == 'DELIVERED':
                    for product in all_order_products:
                        try:
                            user = product.order.user
                            title = f"ORDER {new_status}"
                            body = f"Your {product.product_option} has been {new_status}."
                            image = product.product_option.images_set.first().image if product.product_option.images_set.exists() else None
                            send_user_notification(user, title, body, image)
                        except Exception as e:
                            print(f"Error sending notification: {e}")

                # Get updated data
                updated_products = OrderedProduct.objects.filter(order__id=order_id)
                serializer = ItemOrderSerializer(updated_products, many=True, context={'request': request})

                return Response({
                    'success': True,
                    'message': f'Successfully updated all {updated_count} products to {new_status}',
                    'updated_count': updated_count,
                    'products': serializer.data
                }, status=http_status.HTTP_200_OK)
        else:
            # Update only the single product
            reference_product.status = new_status
            reference_product.save()

            # Send notification if delivered
            if new_status == 'DELIVERED':
                try:
                    user = reference_product.order.user
                    title = f"ORDER {new_status}"
                    body = f"Your {reference_product.product_option} has been {new_status}."
                    image = reference_product.product_option.images_set.first().image if reference_product.product_option.images_set.exists() else None
                    send_user_notification(user, title, body, image)
                except Exception as e:
                    print(f"Error sending notification: {e}")

            serializer = ItemOrderSerializer(reference_product, context={'request': request})

            return Response({
                'success': True,
                'message': f'Successfully updated product status to {new_status}',
                'product': serializer.data
            }, status=http_status.HTTP_200_OK)

    except OrderedProduct.DoesNotExist:
        return Response({
            'error': 'Product not found'
        }, status=http_status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error updating order status: {str(e)}")
        return Response({
            'error': 'An error occurred while updating order status',
            'details': str(e)
        }, status=http_status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def calculate_delivery_charge(request):
    """
    POST payload: { "total_amount": <number> }
    Response:
      {
        "total_amount": <number>,
        "delivery_charge": <0 or 30>,
        "final_amount": <number>
      }
    """
    # Extract and validate total_amount
    try:
        total_amount = float(request.data.get('total_amount', 0))
    except (TypeError, ValueError):
        return Response(
            {"error": "Invalid or missing 'total_amount'"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Apply delivery charge rule
    delivery_charge = 30 if total_amount < 200 else 0


    final_amount = total_amount + delivery_charge

    return Response({
        "total_amount": total_amount,
        "delivery_charge": delivery_charge,
        "final_amount": final_amount
    })


#todo#########informme API

@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticatedUser])  # Changed from IsAuthenticated to IsAuthenticatedUser
def inform_me(request):
    """
    POST: frontend users express interest in a product/option.
    GET:  (admin only) list all InformMe requests.
    """
    # --- POST handler ---
    if request.method == 'POST':
        try:
            # Get data from request
            product_id = request.data.get('product')
            product_option_id = request.data.get('product_option')

            # Validate required fields
            if not product_id:
                return Response(
                    {"error": "Product ID is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get the product
            try:
                product = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return Response(
                    {"error": "Product not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get the product option if provided
            product_option = None
            if product_option_id:
                try:
                    product_option = ProductOption.objects.get(id=product_option_id)
                except ProductOption.DoesNotExist:
                    return Response(
                        {"error": "Product option not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            # Check if user already has a request for this product/option
            existing_request = InformMe.objects.filter(
                user=request.user,
                product=product,
                product_option=product_option
            ).first()

            if existing_request:
                return Response(
                    {"message": "You are already subscribed to notifications for this item"},
                    status=status.HTTP_200_OK
                )

            # Determine prices - offer_price is always on the Product model
            base_price = product.offer_price
            offer_price = request.data.get('offer_price') or base_price

            # Create InformMe record
            inform_me_request = InformMe.objects.create(
                user=request.user,
                product=product,
                product_option=product_option,
                price=base_price,
                offer_price=offer_price
            )

            # Serialize the response
            serialized_data = {
                'id': inform_me_request.id,
                'product': product.title,
                'product_option': product_option.option if product_option else None,
                'price': base_price,
                'offer_price': offer_price,
                'created_at': inform_me_request.created_at.isoformat(),
                'message': 'Successfully registered for stock notifications'
            }

            return Response(serialized_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error in inform_me POST: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    # --- GET handler ---
    elif request.method == 'GET':
        # Only admin users may list all requests
        if not hasattr(request.user, 'is_staff') or not request.user.is_staff:
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            inform_me_requests = InformMe.objects.select_related(
                'user', 'product', 'product_option'
            ).all().order_by('-created_at')

            # Serialize the data manually since you don't have the serializer imported
            serialized_requests = []
            for req in inform_me_requests:
                serialized_requests.append({
                    'id': req.id,
                    'user': req.user.fullname if hasattr(req.user, 'fullname') else req.user.email,
                    'product': req.product.title,
                    'product_option': req.product_option.option if req.product_option else None,
                    'price': req.price,
                    'offer_price': req.offer_price,
                    'created_at': req.created_at.isoformat()
                })

            return Response(serialized_requests, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in inform_me GET: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
def check_inform_me(request):
    """
    Check if user already has an inform me request for a specific product/option

    Query parameters:
    - product_id: Required
    - product_option_id: Optional

    Returns:
    - {"exists": true/false, "request_id": "uuid" (if exists)}
    """
    try:
        product_id = request.GET.get('product_id')
        product_option_id = request.GET.get('product_option_id')

        # Validate required fields
        if not product_id:
            return Response(
                {"error": "product_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if product exists
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if product option exists (if provided)
        product_option = None
        if product_option_id:
            try:
                product_option = ProductOption.objects.get(id=product_option_id)
            except ProductOption.DoesNotExist:
                return Response(
                    {"error": "Product option not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

        # Check if request already exists
        existing_request = InformMe.objects.filter(
            user=request.user,
            product=product,
            product_option=product_option
        ).first()

        if existing_request:
            return Response({
                "exists": True,
                "request_id": str(existing_request.id),
                "created_at": existing_request.created_at.isoformat(),
                "message": "Notification request already exists"
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "exists": False,
                "message": "No existing notification request found"
            }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error in check_inform_me: {str(e)}")
        return Response(
            {"error": "Internal server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def get_client_ip(request):
    """Get the client's IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def version_to_tuple(version_string):
    """Convert version string like '1.2.3' to tuple (1, 2, 3) for comparison"""
    try:
        return tuple(map(int, version_string.split('.')))
    except (ValueError, AttributeError):
        return (0, 0, 0)


@api_view(['POST'])
@permission_classes([AllowAny])
def check_app_version(request):
    """
    Check if app update is available based on admin panel configuration
    """
    try:
        # Validate request data
        data = request.data
        platform = data.get('platform')
        current_version = data.get('current_version')
        current_build = data.get('current_build')

        # Validate required fields
        if not platform or not current_version or not current_build:
            return Response({
                'error': 'Missing required fields',
                'required': ['platform', 'current_version', 'current_build']
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate platform
        if platform not in ['android', 'ios']:
            return Response({
                'error': 'Invalid platform',
                'valid_platforms': ['android', 'ios']
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get latest active version for platform from admin panel
        try:
            latest_version_obj = AppVersion.objects.filter(
                platform=platform,
                is_active=True
            ).first()

            if not latest_version_obj:
                return Response({
                    'error': f'No active version configured for {platform}',
                    'message': 'Please configure version in admin panel'
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return Response({
                'error': 'Database error',
                'message': 'Please try again later'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Compare versions
        current_version_tuple = version_to_tuple(current_version)
        latest_version_tuple = version_to_tuple(latest_version_obj.version_name)
        min_version_tuple = version_to_tuple(latest_version_obj.min_supported_version)

        # Check if update is available
        has_update = latest_version_tuple > current_version_tuple

        # Check if current version is below minimum supported (force update)
        is_below_minimum = current_version_tuple < min_version_tuple
        is_force_update = is_below_minimum or latest_version_obj.is_force_update

        # Prepare response data
        response_data = {
            'has_update': has_update,
            'is_force_update': is_force_update and has_update,
            'current_version': current_version,
            'latest_version': latest_version_obj.version_name,
            'latest_build': latest_version_obj.version_code,
            'min_supported_version': latest_version_obj.min_supported_version,
            'store_url': latest_version_obj.store_url,
            'release_notes': latest_version_obj.release_notes,
        }

        # Set appropriate message based on update type
        if has_update:
            if is_force_update:
                if is_below_minimum:
                    response_data['update_message'] = (
                            latest_version_obj.update_message or
                            f"Your app version is outdated. Please update to v{latest_version_obj.version_name} to continue using ClickWell."
                    )
                else:
                    response_data['update_message'] = (
                            latest_version_obj.update_message or
                            f"Critical update required! Please update to v{latest_version_obj.version_name} immediately."
                    )
            else:
                response_data['update_message'] = (
                        latest_version_obj.update_message or
                        f"A new version v{latest_version_obj.version_name} is available with exciting new features!"
                )
        else:
            response_data['update_message'] = "You have the latest version of ClickWell!"

        # Simple log for debugging (no database storage)
        logger.info(f"Version check - Platform: {platform}, Current: {current_version} (build {current_build}), "
                    f"Latest: {latest_version_obj.version_name} (build {latest_version_obj.version_code}), "
                    f"Has Update: {has_update}, Force: {is_force_update}")

        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Unexpected error in version check: {str(e)}")
        return Response({
            'error': 'Internal server error',
            'message': 'Please try again later'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Test endpoint to verify API is working
@api_view(['GET'])
@permission_classes([AllowAny])
def test_api(request):
    """
    Simple test endpoint to verify API connectivity
    """
    return Response({
        'message': 'ClickWell API is working!',
        'timestamp': datetime.timezone.now(),
        'version': '1.0.0'
    }, status=status.HTTP_200_OK)


# Get current app versions (for debugging)
@api_view(['GET'])
@permission_classes([AllowAny])
def get_app_versions(request):
    """
    Get all active app versions (for debugging)
    """
    try:
        versions = AppVersion.objects.filter(is_active=True)
        data = []

        for version in versions:
            data.append({
                'platform': version.platform,
                'version_name': version.version_name,
                'version_code': version.version_code,
                'min_supported_version': version.min_supported_version,
                'is_force_update': version.is_force_update,
                'store_url': version.store_url,
                'created_at': version.created_at
            })

        return Response({
            'active_versions': data,
            'count': len(data)
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)