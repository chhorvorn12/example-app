<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Models\User;
use Dotenv\Exception\ValidationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{

    /**************
     * return username
     */
    public function username()
    {
        return "email";
    }
    /*******
     * Action login
     */
    public function login(Request $request)
    {
        $this->validate($request, [
            $this->username() => "required |email",
            "password" => "required"
        ]);
        $user = User::where($this->username(), $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => 'The provided credentails are incorrect',
            ]);
        }
        return $user->createToken($request->getClientIp())->plainTextToken;
    }
    /***
     * Action register
     */

    public function register(Request $request)
    {
        $this->validate($request, [
            "name"=>"required",
            $this->username() => "required|email|unique:users",
            "password" => "required|confirmed|string|min:8",
        ]);
        $user=User::create([
            "name"=>$request->name,
            $this->username()=>$request->email,
            "password"=>Hash::make($request->password),
        ]);
        return $user->createToken($request->getClientIp())->plainTextToken;
    }

    public function refresh(Request $request)
    {
        $request->user()->tokens()->delete();
        return  $request->user()->createToken($request->getClientIp())->plainTextToken;
    }

    public function logout()
    {
        Auth::user()->tokens->each(function($token, $key) {
            $token->delete();
        });
        
        return \response()->json([
            'success' => 'Logout successfully'
        ]);
    }
}
