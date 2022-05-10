<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Display a user data.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    /**
     * Store a newly created users in database.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validate = Validator::make($request->all(), [
            'email' => 'email|required|unique:users',
            'username' => 'required|unique:users',
            'password' => 'required'
        ]);

        if ($validate->fails()) {
            return response()
                ->json([
                    'status' => false,
                    'errors' => $validate->errors()
                ]);
        }

        $request['password'] = Hash::make($request->input('password'));
        $user = User::query()->create($request->all());

        $token = $user->createToken($request->input('username'));

        return response()
            ->json([
                'status' => true,
                'user' => $user,
                'token' => $token->plainTextToken,
            ]);
    }

    /**
     * Login user with credentials.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $validate = Validator::make($request->all(), [
            'email' => 'email|required',
            'password' => 'required'
        ]);

        if ($validate->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validate->errors(),
            ]);
        }

        if (!Auth::attempt($request->only([
            'email', 'password'
        ]))) {
            return response()->json([
                'status' => false,
                'message' => 'Email or password incorrect'
            ]);
        }

        $user = Auth::user();
        $token = $user->createToken($user->username)->plainTextToken;

        return response()->json([
            'status' => true,
            'user' => $user,
            'token' => $token
        ]);
    }
}
