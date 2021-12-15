<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * @OA\Post(
     ** path="/api/auth/login",
     *   tags={"Auth"},
     *   summary="Login user",
     *   operationId="login",
     *
     *   @OA\Parameter(
     *      name="email",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *   @OA\Parameter(
     *      name="password",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *          type="string"
     *      )
     *   ),
     *   @OA\Response(
     *      response=200,
     *       description="Success",
     *      @OA\MediaType(
     *           mediaType="application/json",
     *      )
     *   ),
     *   @OA\Response(
     *      response=401,
     *       description="Unauthenticated"
     *   ),
     *   @OA\Response(
     *      response=400,
     *      description="Bad Request"
     *   ),
     *   @OA\Response(
     *      response=404,
     *      description="Not found"
     *   ),
     *      @OA\Response(
     *          response=403,
     *          description="Forbidden"
     *      ),
     *     @OA\Response(
     *          response=422,
     *          description="Validation error"
     *      )
     *)
     **/

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors())->setStatusCode(Response::HTTP_UNPROCESSABLE_ENTITY,
                Response::$statusTexts[Response::HTTP_UNPROCESSABLE_ENTITY]);
        }

        if (!$token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'])->setStatusCode(Response::HTTP_FORBIDDEN,
                Response::$statusTexts[Response::HTTP_FORBIDDEN]);;
        }

        return $this->createNewToken($token);
    }

    /**
     * @OA\Post(
     ** path="/api/auth/register",
     *   tags={"Auth"},
     *   summary="Register new user",
     *   operationId="register",
     *
     *  @OA\Parameter(
     *      name="name",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *  @OA\Parameter(
     *      name="email",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *   @OA\Parameter(
     *      name="password",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *      @OA\Parameter(
     *      name="password_confirmation",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *   @OA\Response(
     *      response=201,
     *       description="Success",
     *      @OA\MediaType(
     *           mediaType="application/json",
     *      )
     *   ),
     *   @OA\Response(
     *      response=401,
     *       description="Unauthenticated"
     *   ),
     *   @OA\Response(
     *      response=400,
     *      description="Bad Request "
     *   ),
     *   @OA\Response(
     *      response=404,
     *      description="Not found"
     *   ),
     *      @OA\Response(
     *          response=403,
     *          description="Forbidden"
     *      ),
     *     @OA\Response(
     *          response=422,
     *          description="Validation error"
     *      )
     *)
     **/

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:6',
        ]);

            if ($validator->fails()) {
                return response()->json($validator->errors())->setStatusCode(Response::HTTP_UNPROCESSABLE_ENTITY,
                    Response::$statusTexts[Response::HTTP_UNPROCESSABLE_ENTITY]);
            }
            $filename = uniqid().'.'.$request->file('Image')->extension();
            $path = public_path('uploads');
            $request->file('Image')->move($path, $filename);

            $user = User::create(array_merge(
                $validator->validated(),
                ['password' => bcrypt($request->password),
                    'Image' =>$filename]
            ));
        if(!$token = auth()->attempt($validator->validated()))
        {
            return response()->json(['error' => 'Дані введено не коректно!'], 401);
        }
            return response()->json(['user' => $user,
                'access_token' => $token  ])->setStatusCode(Response::HTTP_CREATED,
                Response::$statusTexts[Response::HTTP_CREATED]);
        //}
    }

        /**
         * @OA\Post(
         *     path="/api/auth/logout",
         *     tags={"Auth"},
         *     security={{"apiAuth":{}}},
         *     @OA\Response(response="200", description="Display a listing of projects.")
         * )
         */
        /**
         * Log the user out (Invalidate the token).
         *
         * @return \Illuminate\Http\JsonResponse
         */
        public
        function logout()
        {
            auth()->logout();

            return response()->json(['message' => 'User successfully signed out'])->setStatusCode(Response::HTTP_OK,
                Response::$statusTexts[Response::HTTP_OK]);
        }

        /**
         * @OA\Post(
         *     path="/api/auth/refresh",
         *     tags={"Auth"},
         *     security={{"apiAuth":{}}},
         *     @OA\Response(response="200", description="Display a listing of projects.")
         * )
         */
        /**
         * Refresh a token.
         *
         * @return \Illuminate\Http\JsonResponse
         */
        public
        function refresh()
        {
            return $this->createNewToken(auth()->refresh())->setStatusCode(Response::HTTP_OK,
                Response::$statusTexts[Response::HTTP_OK]);
        }

        /**
         * Get the authenticated User.
         *
         * @return \Illuminate\Http\JsonResponse
         */
        /**
         * @OA\Get(
         *     path="/api/auth/user-profile",
         *     tags={"Auth"},
         *     summary="Profile user",
         *     security={{"apiAuth":{}}},
         *     @OA\Response(response="200", description="Display a listing of projects.")
         * )
         */

        public
        function userProfile()
        {
            return response()->json(auth()->user())->setStatusCode(Response::HTTP_OK,
                Response::$statusTexts[Response::HTTP_OK]);
        }

        /**
         * Get the token array structure.
         *
         * @param string $token
         *
         * @return \Illuminate\Http\JsonResponse
         */
        protected
        function createNewToken($token)
        {
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60,
                'user' => auth()->user()
            ])->setStatusCode(Response::HTTP_OK, Response::$statusTexts[Response::HTTP_OK]);
        }


}
