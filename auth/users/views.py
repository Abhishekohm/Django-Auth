from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.exceptions import AuthenticationFailed, NotFound
from .models import User
from .serializers import UserSerializer, AuthUserSerializer
from .decorators import login_required
import jwt
# Create your views here.


@api_view(['POST'])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    # print(username, password)
    if username is None or password is None:
        raise AuthenticationFailed(code=401)

    user = User.objects.filter(username=username).first()
    if user is None:
        raise NotFound(code=404)
    instance = user
    user = AuthUserSerializer(user).data
    access_token = instance.getAccessToken()
    refresh_token = instance.getRefreshToken()
    print('access_token => ', access_token)
    print('refresh_token => ', refresh_token)
    response = Response({
        'user': user,
        'access_token': access_token
    })
    response.set_cookie('jwt_refresh_token', refresh_token, httponly=True)
    return response


@api_view(['POST'])
def register(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    if username is None or password is None or email is None:
        raise AuthenticationFailed(code=401)

    instance = User(username=username, email=email)
    instance.password = make_password(password)
    instance.save()
    user = UserSerializer(instance).data
    access_token = instance.getAccessToken()
    refresh_token = instance.getRefreshToken()
    print('access_token => ', access_token)
    print('refresh_token => ', refresh_token)
    response = Response({
        'user': user,
        'access_token': access_token
    })
    response.set_cookie('jwt_refresh_token', refresh_token, httponly=True)
    print(response)
    return response


@api_view(['GET'])
@login_required
def private(request):
    return Response({
        'message': 'private route hit'
    })


@api_view(['GET'])  # debugging remaining
def refresh(request):
    refresh_token = request.COOKIES.get('jwt_refresh_token')
    if refresh_token is None:
        return Response(status=401)
    user = User.objects.filter(refresh_token=refresh_token).first()
    try:
        payload = jwt.decode(refresh_token, 'secret', algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return Response(status=404)
    if user.id != payload.id:
        return Response(status=400)

    access_token = user.getAccessToken()
    return Response({
        access_token: access_token
    })
